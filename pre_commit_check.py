from hash_identifier import identify
import sys

def check_file(filepath: str) -> list[str]:
    """Trả về danh sách các cảnh báo tìm thấy trong file này."""
    warnings = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_number, line in enumerate(f, start=1):
            if "# pragma: allow-hash" in line:
                continue

            tokens = line.split()

            for token in tokens:
                token = token.strip("\"'(),[]{}:;")

                if not token:
                    continue

                result = identify(token)

                if result:
                    for candidate in result:
                        if (
                            candidate.confidence_label == "high"
                            and candidate.algorithm.lower() not in ("generic phc", "not-a-hash")
                        ):
                            warnings.append(
                                f"{filepath}:{line_number}: "
                                f"{token} looks like {candidate.algorithm}"
                            )
                            break

    return warnings

def main() -> int:
    filepaths = sys.argv[1:]
    all_warnings = []

    for filepath in filepaths:
        all_warnings.extend(check_file(filepath))

    if all_warnings:
        print("Commit blocked — possible hash(es) found:")

        for warning in all_warnings:
            print(f"  {warning}")

        print(
            "\nIf these are intentional (e.g. test fixtures), "
            "add '# pragma: allow-hash' to the line."
        )

        return 1

    return 0


if __name__ == "__main__":
    exit(main())