# Add data into RS testmeans pickup point simulators


To add data to simulators, follow these steps to configure the **config** folder for each station. The required files 
for the CADIP simulator should be structured as follows:

- "auth.json" - File containing the basic auth credentials.
- "Catalogue/FileResponse.json" - File containing the JSON response with metadata for each file.
- "Catalogue/QualityInfoResponse.json" - File containing the JSON response with quality info for each session.
- "Catalogue/SPJ.json" - File containing the JSON response for each session added.

The actual files should be placed into **config/S3Mock/** directory.

### Example: Add a complete session by overwritting an existing one.

1. Modify the **SPJ.json** file by adding your session metadata as shown below:
```json
    {
      "Id": "6f3c8d91-2b0e-492d-aef6-87b24f2bcb1e",
      "SessionId": "S1A_20210410031928012345",
      "NumChannels": 2,
      "PublicationDate": "2021-04-10T03:39:28.012Z",
      "Satellite": "S1A",
      "StationUnitId": "01",
      "DownlinkOrbit": 53186,
      "AcquisitionId": "53186_1",
      "AntennaId": "MSP21",
      "FrontEndId": "01",
      "Retransfer": false,
      "AntennaStatusOK": true,
      "FrontEndStatusOK": true,
      "PlannedDataStart": "2021-04-10T03:19:28.012Z",
      "PlannedDataStop": "2021-04-10T03:29:28.012Z",
      "DownlinkStart": "2021-04-10T03:19:28.012Z",
      "DownlinkStop": "2021-04-10T03:29:28.012Z",
      "DownlinkStatusOK": true,
      "DeliveryPushOK": true
    }
```

2. Add the actual files into **config/S3Mock/** directory.
```shell
ll src/CADIP/config/S3Mock 
total 1688
-rw-r--r--  1 ovidiu  staff    85B Apr 19 11:33 DCS_01_S1A_20200105072204051312_ch1_DSDB_00000.raw
-rw-r--r--  1 ovidiu  staff   219B Apr 19 11:33 DCS_01_S1A_20200105072204051312_ch1_DSDB_00001.raw
```

3. For each file, add the metadata response to **Catalogue/FileResponse.json**:
```json
{
  "Id": "e4d17d2f-29eb-4c18-bc1f-bf2769a3a16d",
  "Name": "DCS_01_S1A_20200105072204051312_ch1_DSDB_00000.raw",
  "SessionID": "S1A_20200105072204051312",
  "Channel": 1,
  "BlockNumber": 1,
  "FinalBlock": false,
  "PublicationDate": "2020-01-05T18:52:29.165Z",
  "EvictionDate": "2020-01-05T18:52:29.165Z",
  "Size": "42",
  "Retransfer": false
},
{
  "Id": "cd24aa8b-2719-4a1e-b4a7-f7c9df6de300",
  "Name": "DCS_01_S1A_20200105072204051312_ch1_DSDB_00001.raw",
  "SessionID": "S1A_20200105072204051312",
  "Channel": 1,
  "BlockNumber": 1,
  "FinalBlock": false,
  "PublicationDate": "2020-01-05T18:52:32.165Z",
  "EvictionDate": "2020-01-05T18:52:32.165Z",
  "Size": "51",
  "Retransfer": false
}
```

### Example 2: Add data using "-c" flag.
With files already placed in a custom location, start the docker image by passing the path using -c flag.
```shell
docker exec cadip_container poetry run python3.11 /opt/cadip/cadip_station_mock.py -H 127.0.0.1 -p 8080 -c /your/dir/

```

To use the *$expand=Files* option for a simulated station, you can use the --expand flag while running the container:

```shell
docker exec cadip_container poetry run python3.11 /opt/cadip/cadip_station_mock.py -H 127.0.0.1 -p 8080 --expand True

```

By following these steps, you can successfully add data to the RS testmeans pickup point simulators and configure the 
sessions as needed.