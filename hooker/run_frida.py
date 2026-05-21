"""
Frida 런타임 훅 실행기

사용 예시
---------
  # 프로세스 스폰
  python run_frida.py --spawn C:\\malware\\sample.exe

  # 실행 중인 PID에 붙기
  python run_frida.py --pid 1234

  # 프로세스 이름으로 붙기
  python run_frida.py --name notepad.exe
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import frida
except ImportError:
    sys.exit("[!] frida 패키지가 설치되지 않았습니다: pip install frida frida-tools")

_HOOKS_PATH = Path(__file__).parent / "frida_hooks.js"


def load_hooks() -> str:
    if not _HOOKS_PATH.exists():
        sys.exit(f"[!] 훅 파일 없음: {_HOOKS_PATH}")
    return _HOOKS_PATH.read_text(encoding="utf-8")


def on_message(message: dict, data) -> None:
    if message["type"] == "send":
        print(f"[frida] {message['payload']}")
    elif message["type"] == "error":
        print(f"[frida ERROR] {message['description']}", file=sys.stderr)


def attach_spawn(target_path: str, script_src: str) -> None:
    """대상 프로세스를 스폰하고 훅 주입"""
    device = frida.get_local_device()
    pid = device.spawn([target_path])
    print(f"[*] 스폰됨: {target_path} (PID={pid})")

    session = device.attach(pid)
    script = session.create_script(script_src)
    script.on("message", on_message)
    script.load()
    print("[*] 훅 로드 완료 — 프로세스 재개")
    device.resume(pid)
    _wait(session)


def attach_pid(pid: int, script_src: str) -> None:
    """실행 중인 PID에 훅 주입"""
    session = frida.attach(pid)
    print(f"[*] PID {pid} 에 붙었습니다")
    script = session.create_script(script_src)
    script.on("message", on_message)
    script.load()
    print("[*] 훅 로드 완료")
    _wait(session)


def attach_name(name: str, script_src: str) -> None:
    """프로세스 이름으로 훅 주입"""
    session = frida.attach(name)
    print(f"[*] '{name}' 에 붙었습니다")
    script = session.create_script(script_src)
    script.on("message", on_message)
    script.load()
    print("[*] 훅 로드 완료")
    _wait(session)


def _wait(session) -> None:
    print("[*] Ctrl+C 를 눌러 종료")
    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()
        print("[*] 세션 종료")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Frida 런타임 훅으로 샌드박스 회피 기법 무력화",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python run_frida.py --spawn C:\\\\sample.exe
  python run_frida.py --pid 1234
  python run_frida.py --name notepad.exe
""",
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--spawn", metavar="PATH", help="대상 EXE 스폰 후 훅 주입")
    group.add_argument("--pid",   metavar="PID",  type=int, help="실행 중인 PID에 붙기")
    group.add_argument("--name",  metavar="NAME", help="프로세스 이름으로 붙기")
    return p


def main() -> None:
    args = build_parser().parse_args()
    script_src = load_hooks()

    if args.spawn:
        attach_spawn(args.spawn, script_src)
    elif args.pid:
        attach_pid(args.pid, script_src)
    else:
        attach_name(args.name, script_src)


if __name__ == "__main__":
    main()
