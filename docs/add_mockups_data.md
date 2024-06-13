# Add data into RS testmeans CADIP simulator


To add data into the CADIP simulator, follow these steps to populate the **config** folder for each station.
The required files for the CADIP simulator should be structured as follows:

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
ovidiu@MBP2023 rs-testmeans % ll src/CADIP/config/S3Mock
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

# Add data into RS testmeans ADGS simulator

In the similar way, your custom data directory should have the following signature:

- "auth.json" - File containing the basic auth credentials.
- "Catalog/GETFileResponse.json" - File containing JSON metadata for each AUX.

Files should be placed in **Storage** directory.

### Example: Add an AUX file overwriting current structure.

1. Modify the **GETFileResponse.json** file by adding your session metadata as shown below:
```json
{
  "Id": "2b17b57d-fff4-4645-b539-91f305c27c69",
  "Name": "S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000.TGZ",
  "ContentType": "application/octet-stream",
  "ContentLength": "8326253",
  "OriginDate": "2018-01-17T12:56:05.232Z",
  "PublicationDate": "2019-02-16T12:00:00.000Z",
  "EvictionDate": "2019-02-23T12:00:00.000Z",
  "Checksum": [
    {
      "Algorithm": "MD5",
      "Value": "E8A303BF3D85200514F727DB60E7DB65",
      "ChecksumDate": "2019-02-16T12:00:00.000Z"
    }
  ],
  "ContentDate": {
    "Start": "2019-02-17T09:00:00.000Z",
    "End": "2019-02-17T21:00:00.000Z"
  }
}
```

2. Add the actual files into **config/Storage/** directory.
```shell
ovidiu@MBP2023 rs-testmeans % ll src/ADGS/config/Storage
total 744
-rw-r--r--  1 ovidiu  staff   542B Apr 19 11:33 S1A_AUX_PP2_V20200106T080000_G20200106T080000.SAFE
-rw-r--r--  1 ovidiu  staff   833B Apr 19 11:33 S1A_AUX_PP2_V20200121T080000_G20200121T080000.SAFE
```

### Example 2: Add data using "-c" flag.
With files already placed in a custom location, start the docker image by passing the path using -c flag.
```shell
docker exec adgs_container poetry run python3.11 /opt/adgs/adgs_station_mock.py -H 127.0.0.1 -p 8080 -c /your/dir/

```

# Usage on cluster

The modified simulated data should be persistent even after a pod restart. To achieve this, Persistent Volume Claims (PVC) are mounted in the directories from where the simulator may use the files found there.
The other config files are anyway created as configuration maps for each pod.

## CADIP simulator
A pvc is mounted in **config/S3Mock/** directory. The operator should perform a git pull of the rs-testmeans project on his/her local pc. This allows the access to the simulated data from the **rs-testmeans/src/CADIP/config/S3Mock** directory. When the pod is first created with the pvc mounted in **config/S3Mock/** directory, the operator should manually copy all the files from his/her computer to this location. This is requested at the pod initialization only. Whenever the pod is restarted, the files will be persistent.
The **SPJ.json** and **Catalogue/FileResponse.json** files are deployed as configuration maps. To add a session or to add more files, one should copy the files to **config/S3Mock/** (now mounted as pvc) and follow the steps [1 and 2 from adding data to CADIP simulator](#add-data-into-rs-testmeans-cadip-simulator). Kind reminder that for the cluster, the **SPJ.json** and **Catalogue/FileResponse.json** are configuration maps, and should be treated accordingly.

## ADGS simulator
A pvc is mounted in **config/Storage/** directory. The operator should perform a git pull of the rs-testmeans project on his/her local pc. This allows the access to the simulated data from the **rs-testmeans/src/ADGS/config/Storage** directory. When the pod is first created with the pvc mounted in **config/Storage/** directory, the operator should manually copy all the files from his/her computer to this location. This is requested at the pod initialization only. Whenever the pod is restarted, the files will be persistent.
The **Catalog/GETFileResponse.json** file is deployed as a configuration map. To add more files, one should copy the files to **config/Storage/** (now mounted as pvc) and follow the step [1 from adding data to ADGS simulator](#add-data-into-rs-testmeans-adgs-simulator). Kind reminder that for the cluster, the **Catalogue/FileResponse.json** is a configuration map, and should be treated accordingly.
