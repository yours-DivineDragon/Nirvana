import json
import sys

value = json.load(sys.stdin)
json.dump({"result": value["value"] // 2}, sys.stdout)
