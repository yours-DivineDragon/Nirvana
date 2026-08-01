import json
import sys

value = json.load(sys.stdin)
json.dump({"result": round(value["value"] / 2)}, sys.stdout)
