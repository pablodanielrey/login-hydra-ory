import json
import utils

if __name__ == '__main__':
    r = utils.get_policies()
    print(json.dumps(r, indent=4, sort_keys=True))
