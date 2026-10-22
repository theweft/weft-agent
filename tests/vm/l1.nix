# SPDX-FileCopyrightText: 2026 The weft authors
# SPDX-License-Identifier: MIT
#
# L1 end to end on a real system: the shipped systemd units (dist/systemd/), the decider
# sandboxed as user weft, two read-only USB sticks with signed documents, and a power cut in
# the middle of a round.
#
#   nix build .#checks.x86_64-linux.l1-vm --override-input weft-verifier git+file:../weft-verifier -L
{
  pkgs,
  weft-agent,
  fixtures,
}:
let
  # A read-only VFAT stick with the fixture documents of one directory.
  stick =
    name: label:
    pkgs.runCommand "weft-${name}.img"
      {
        nativeBuildInputs = [
          pkgs.dosfstools
          pkgs.mtools
        ];
      }
      ''
        truncate -s 4M $out
        mkfs.vfat -n ${label} $out
        for f in ${fixtures}/${name}/*; do mcopy -i $out "$f" ::/; done
      '';
  # Hooks report success only once their effect is durable (like an OTA tool before it
  # switches slots): append, then fsync.
  installHook = pkgs.writeShellScript "weft-install" ''
    echo "$WEFT_COMPONENT $WEFT_ARTIFACT" >> /var/log/weft-installs.log
    sync /var/log/weft-installs.log
  '';
  configHook = pkgs.writeShellScript "weft-reload" ''
    echo "$WEFT_COMPONENT $WEFT_CONFIG_HASH" >> /var/log/weft-configs.log
    sync /var/log/weft-configs.log
  '';
in
pkgs.testers.runNixOSTest {
  name = "weft-l1";

  nodes.device =
    { modulesPath, ... }:
    {
    # A slim system, closer to an embedded device: no documentation, no default tools.
    imports = [ "${modulesPath}/profiles/minimal.nix" ];
    virtualisation.memorySize = 1024;
    virtualisation.qemu.options = [
      "-drive file=${stick "stick1" "WEFT1"},format=raw,if=virtio,readonly=on"
      "-drive file=${stick "stick2" "WEFT2"},format=raw,if=virtio,readonly=on"
    ];
    # Stick 1 is plugged in at boot. (In test VMs, virtualisation.fileSystems replaces fileSystems.)
    virtualisation.fileSystems."/media/weft-usb" = {
      device = "/dev/disk/by-label/WEFT1";
      fsType = "vfat";
      options = [
        "ro"
        "nofail"
      ];
    };

    users.users.weft = {
      isSystemUser = true;
      group = "weft";
    };
    users.groups.weft = { };

    # The units exactly as shipped, from the package.
    systemd.packages = [ weft-agent ];
    systemd.services.weft-executor.wantedBy = [ "multi-user.target" ];
    systemd.services.weft-decider.wantedBy = [ "multi-user.target" ];
    systemd.tmpfiles.rules = [ "d /etc/weft/config 0755 root root -" ];

    environment.etc."weft/anchors/root.pub".source = "${fixtures}/root.pub";
    environment.etc."weft/decider.env".text = ''
      WEFT_TENANT=acme
      WEFT_DECIDER_ARGS=--name vm --anchor /etc/weft/anchors/root.pub --label line=l1 --inbox /media/weft-usb --interval 1
    '';
    environment.etc."weft/executor.env".text = ''
      WEFT_CONFIG_DIR=/etc/weft/config
      WEFT_ON_CONFIG=${configHook}
      WEFT_ON_INSTALL=${installHook}
    '';
    # Tools the test script itself uses.
    environment.systemPackages = [ pkgs.jq ];
  };

  testScript = ''
    import hashlib, json, random, re, time

    ARTIFACT = "a1" * 32

    def read_json(path):
        return json.loads(device.succeed(f"cat {path}"))

    def config():
        return read_json("/etc/weft/config/app.json")

    def report():
        return read_json("/var/lib/weft/outbox/report.json")

    def installs():
        return device.succeed("cat /var/log/weft-installs.log").splitlines()

    def insert_stick(label):
        device.succeed("systemctl stop weft-decider")
        device.succeed("umount /media/weft-usb || true")
        device.succeed(f"mount -o ro /dev/disk/by-label/{label} /media/weft-usb")
        device.succeed("systemctl start weft-decider")

    device.start()
    device.wait_for_unit("weft-executor.service")
    device.wait_for_unit("weft-decider.service")

    def diagnose():
        pid = device.succeed("systemctl show -p MainPID --value weft-decider").strip()
        for cmd in [
            "findmnt /media/weft-usb || true",
            "ls -la /media/weft-usb || true",
            f"nsenter -t {pid} -m -- ls -la /media/weft-usb || true",
            f"nsenter -t {pid} -m -- findmnt -o TARGET,PROPAGATION /media/weft-usb / || true",
            f"tr '\\0' ' ' < /proc/{pid}/cmdline",
            "cat /var/lib/weft/outbox/report.json || true",
            "ls -la /var/lib/weft /var/lib/weft/documents || true",
            "journalctl -u weft-executor -u weft-decider --no-pager | grep -v 'round: 0' | tail -20",
        ]:
            device.log(f"$ {cmd}\n{device.execute(cmd)[1]}")

    with subtest("stick 1: configuration applied, artifact installed once"):
        try:
            device.wait_until_succeeds("test -s /var/log/weft-installs.log", timeout=30)
        except Exception:
            diagnose()
            raise
        device.wait_until_succeeds("jq -e '.limit == 10' /etc/weft/config/app.json", timeout=30)
        assert config() == {"limit": 10, "rate": 5}, config()
        r = report()
        assert r["conflicts"] == [] and r["withheld"] == [] and r["failed"] == [], r
        assert installs() == [f"app {ARTIFACT}"], installs()

    with subtest("the decider is sandboxed"):
        pid = device.succeed("systemctl show -p MainPID --value weft-decider").strip()
        status = device.succeed(f"cat /proc/{pid}/status")
        assert "NoNewPrivs:\t1" in status, status
        assert re.search(r"CapEff:\t0+\n", status), status
        assert device.succeed(f"stat -c %U /proc/{pid}").strip() == "weft"
        net = device.succeed(f"readlink /proc/{pid}/ns/net")
        assert net != device.succeed("readlink /proc/1/ns/net"), "decider shares the host network"
        # Read-only system in the decider's mount namespace, even for root.
        device.fail(f"nsenter -t {pid} -m -- touch /etc/weft/config/x")
        device.fail(f"nsenter -t {pid} -m -- touch /usr/x")
        out = device.succeed("systemd-analyze security --no-pager weft-decider.service")
        match = re.search(r"Overall exposure level for weft-decider\.service: ([0-9.]+)", out)
        assert match is not None, out
        score = float(match.group(1))
        device.log(f"systemd-analyze exposure of weft-decider: {score}")
        assert score <= 2.5, out

    with subtest("stick 2 and a power cut during the round"):
        insert_stick("WEFT2")
        time.sleep(random.uniform(0.0, 1.5))
        device.crash()
        device.start()
        device.wait_for_unit("weft-decider.service")
        # Whatever the moment of the cut, the configuration is one of the two versions, whole.
        assert config() in ({"limit": 10, "rate": 5}, {"limit": 10, "rate": 7}), config()

    with subtest("after the reboot: converges, forged document rejected, no reinstall"):
        insert_stick("WEFT2")
        device.wait_until_succeeds("jq -e '.rate == 7' /etc/weft/config/app.json", timeout=30)
        assert config() == {"limit": 10, "rate": 7}, config()
        forged = hashlib.sha256(open("${fixtures}/stick2/forged.cose", "rb").read()).hexdigest()
        device.wait_until_succeeds(
            f"jq -e '.quarantined | index(\"{forged}\")' /var/lib/weft/outbox/report.json",
            timeout=30,
        )
        r = report()
        assert r["withheld"] == [] and r["failed"] == [], r
        stored = device.succeed("ls /var/lib/weft/documents").split()
        assert len(stored) == 5, stored  # 4 from stick 1, fleet v2; the forged one is not kept
        assert installs() == [f"app {ARTIFACT}"], installs()
  '';
}
