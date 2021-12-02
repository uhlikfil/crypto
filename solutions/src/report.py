import colorama
from colorama import Fore
from colorama.ansi import AnsiFore

colorama.init()


def colored(text: str, color: AnsiFore) -> str:
    return f"{color}{text!r}{Fore.RESET}"


def mark_exercise(ex_id) -> None:
    msg = colored(f"=== Exercise {ex_id} ===", Fore.YELLOW)
    print(f"\n{msg}")


def ct(text: str) -> str:
    return f"{colored(text, Fore.RED)}"


def pt(text: str) -> str:
    return f"{colored(text, Fore.GREEN)}"


def k(text: str) -> str:
    return f"{colored(text, Fore.BLUE)}"


if __name__ == "__main__":
    import importlib

    done_labs = 4

    for i in range(1, done_labs + 1):
        if i > 1:
            print("\n\n")
        print(f"LAB {i}")
        lab = importlib.import_module(f"lab_{i}")
        lab.main()
