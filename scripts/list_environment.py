from dotenv import load_dotenv
load_dotenv()
import os

for param in os.environ.keys():
    print("{} {}".format(param,os.environ[param]))
