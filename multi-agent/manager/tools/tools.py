from datetime import datetime


def get_current_time() -> dict:
    """
    Get the current time in the format YYYYMMDD_HHMMSS
    """
    return {
        "current_time": datetime.now().strftime("%Y%m%d_%H%M%S"),
    }

def write_report(report_name: str, report_contents: str):
    """Write a report to a file.

    Args:
        report_name: The name of the report.
        report_contents: The contents of the report.

    """
    now = get_current_time()["current_time"]
    with open(f"../reports/{report_name}_{now}.md", "w") as f:
        f.write(f"{report_contents}")
