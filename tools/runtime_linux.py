"""Actual native egui runtime under Xvfb + llvmpipe; no real profiles or secret service."""
import json
import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import tempfile


def run(output):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dirlark-render-") as temp:
        scratch = Path(temp)
        env = os.environ.copy()
        env.update(LIBGL_ALWAYS_SOFTWARE="1", GALLIUM_DRIVER="llvmpipe", XDG_SESSION_TYPE="x11", DBUS_SESSION_BUS_ADDRESS="unix:path=/tmp/dirlark-no-session-bus", XDG_CONFIG_HOME=str(scratch / "config"), XDG_RUNTIME_DIR=str(scratch))
        env.pop("WAYLAND_DISPLAY", None)
        with (scratch / "xvfb.log").open("w") as log:
            server = subprocess.Popen(["Xvfb", "-displayfd", "1", "-screen", "0", "1280x900x24", "-nolisten", "tcp", "-ac"], stdout=subprocess.PIPE, stderr=log)
            try:
                if not select.select([server.stdout], [], [], 15)[0]:
                    raise RuntimeError("Xvfb did not start")
                display = server.stdout.readline().decode().strip()
                if not display.isdecimal():
                    raise RuntimeError("Xvfb did not provide a display")
                env["DISPLAY"] = ":" + display
                gl = subprocess.check_output(["glxinfo", "-B"], env=env, text=True, timeout=20)
                renderer = next((line.strip() for line in gl.splitlines() if "OpenGL renderer string" in line), "")
                if "llvmpipe" not in renderer.lower():
                    raise RuntimeError("Expected Mesa llvmpipe software GL")
                subprocess.run(["cargo", "run", "--locked", "--example", "keyring_unavailable"], env=env, check=True, timeout=120)
                png = scratch / "connection-screen.png"
                env["DIRLARK_SMOKE_SCREENSHOT"] = str(png)
                target = Path(env.get("CARGO_TARGET_DIR", "target"))
                subprocess.run([str((target / "debug/dirlark").resolve()), "--smoke"], env=env, check=True, timeout=40)
                receipt = json.loads(png.with_suffix(".json").read_text())
                data = png.read_bytes()
                if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                    raise RuntimeError("No renderer PNG")
                width, height = struct.unpack(">II", data[16:24])
                if not (width >= 900 and height >= 600 and receipt["width"] == width and receipt["height"] == height and receipt["distinct_colors"] > 8 and receipt["connection_screen_visible"] and receipt["screen"] == "connection" and receipt["credential_storage_available"] is False):
                    raise RuntimeError("Connection-screen or unavailable-service evidence failed")
                shutil.copyfile(png, output / png.name)
                return {"platform": "linux-x86_64", "renderer": renderer, "gui_exit_code": 0, "secret_service": "unavailable-explicit-no-plaintext", "capture": receipt}
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    print(json.dumps(run(Path("/tmp/dirlark-evidence")), indent=2))
