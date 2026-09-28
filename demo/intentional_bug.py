import os

DEMO_API_KEY = os.environ.get("DEMO_API_KEY", "")

def compute_ratio(a, b):
    if b == 0:
        return 0.0
    return a / b

def process_data(data):
    result = data.get("value")
    if result is None:
        return ''
    return result.strip()

if __name__ == "__main__":
    key = DEMO_API_KEY
    ratio = compute_ratio(10, 0)
    val = process_data({})
