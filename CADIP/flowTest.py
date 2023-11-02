import requests
import json


def realUsageTest():
    print("Querrying CADIP for products made public on 2019-02-16", end="\n\n\n")
    data = requests.get(
        "http://127.0.0.1:5000/Sessions?filter=PublicationDate eq 2019-02-16"
    )
    if data.content:
        print(f"CADIP response: {data.content}", end="\n\n\n")
    else:
        print("CADIP cannot find requested session", end="\n\n\n")
    file_id = json.loads(data.content)["Id"]
    print(f"Selecting file with ID {file_id}", end="\n\n\n")

    print("Querrying CADIP for file with that id", end="\n\n\n")
    data = requests.get(f"http://127.0.0.1:5000/Files?filter=Id eq {file_id}")

    if data.content:
        print(f"CADIP response: {data.content}", end="\n\n\n")
        print("File found, downloading ...", end="\n\n\n")
        data = requests.get(f"http://127.0.0.1:5000/Files({file_id})")
        if data.status_code == 200:
            print("Successful!")
    else:
        print("CADIP cannot find requested file")


if __name__ == "__main__":
    realUsageTest()
