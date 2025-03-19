# Add data on mockups

## Add data into RS testmeans CADIP simulator

To add data into the CADIP simulator, follow these steps to populate the **config** folder for each station.
The required files for the CADIP simulator should be structured as follows:

- "auth_tmp.json" - File containing the basic auth credentials.
- "Catalogue/FileResponse.json" - File containing the JSON response with metadata for each file.
- "Catalogue/QualityInfoResponse.json" - File containing the JSON response with quality info for each session.
- "Catalogue/SPJ.json" - File containing the JSON response for each session added.

The actual files should be placed into **config/S3Mock/** directory.

### Example 1: Add a complete session by overwritting an existing one

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

### Example 2: Add data using "-c" flag

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

## Add data into RS testmeans ADGS simulator

In the similar way, your custom data directory should have the following signature:

- "auth_tmp.json" - File containing the basic auth credentials.
- "Catalog/GETFileResponse.json" - File containing JSON metadata for each AUX.

Files should be placed in **Storage** directory.

### Example 1: Add an AUX file overwriting current structure

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

### Example 2: Add data using "-c" flag

With files already placed in a custom location, start the docker image by passing the path using -c flag.

```shell
docker exec adgs_container poetry run python3.11 /opt/adgs/adgs_station_mock.py -H 127.0.0.1 -p 8080 -c /your/dir/
```

## Usage on cluster (Kubernetes)

The modified simulated data should be persistent even after a pod restart. To achieve this, Persistent Volume Claims (PVC) are used, and a volume is assigned to the POD.

### CADIP simulator data

A volume is mounted in **/opt/cadip/config/S3Mock/** directory inside the CADIP mockup pod.

The folder **/opt/cadip/config/S3Mock/** is created empty the first time.

#### Dummy files (Optionnal)

If one still wants to use the dummy files provided in the source code of the mockup, he should copy them manually.

Perform a git pull of the rs-testmeans project on the local pc and access the simulated data from the **rs-testmeans/src/CADIP/config/S3Mock** directory.

Then simply make an archive of the files :

```shell
cd rs-testmeans/src/CADIP/config/S3Mock
tar -zcvf dummy_files.tgz *
```

Copy it from the source code to the desired mockup-station-cadip pod :

```shell
kubectl -n processing cp dummy_files.tgz mockup-station-cadip-mti-76d59f4f84-4cjnv:/opt/cadip/config/S3Mock/dummy_files.tgz
```

And finally uncompress the archive on the pod :

```shell
kubectl -n processing exec -ti mockup-station-cadip-mti-76d59f4f84-4cjnv -- bash
cd /opt/cadip/config/S3Mock
tar -zxvf dummy_files.tgz
```

#### Real files

Copy the files to the pod :

```shell
kubectl -n processing cp file1 mockup-station-cadip-mti-76d59f4f84-4cjnv:/opt/cadip/config/S3Mock/file1
kubectl -n processing cp file2 mockup-station-cadip-mti-76d59f4f84-4cjnv:/opt/cadip/config/S3Mock/file2
[...]
kubectl -n processing cp fileN mockup-station-cadip-mti-76d59f4f84-4cjnv:/opt/cadip/config/S3Mock/fileN
```

Note: If you have many files, you can create an archive, copy it on the pod and uncompress it on the pod with the `tar` command.

### CADIP simulator config

There are 4 configuration files managed as ConfigMap :

- Catalogue/SPJ.json
- Catalogue/FileResponse.json
- Catalogue/QualityInfoResponse.json
- auth_tmp.json

Refer to [Add data into RS testmeans CADIP simulator](#add-data-into-rs-testmeans-cadip-simulator)

To add a session or to add more files, one should :

1. Copy the files to **/opt/cadip/config/S3Mock/** (Done in previous steps)

2. Edit the 3 configuration files of the **Catalogue** folder :

   ```shell
   kubectl -n processing edit cm mockup-station-cadip-mti-catalog-config
   kubectl -n processing edit cm mockup-station-cadip-mti-quality-config
   kubectl -n processing edit cm mockup-station-cadip-mti-sessionid-config
   ```

3. Restart the pod (`kubectl -n processing rollout restart deploy mockup-station-cadip-mti`)

### ADGS simulator data

A volume is mounted in **/opt/adgs/config/Storage/** directory inside the ADGS mockup pod.

The folder **/opt/adgs/config/Storage/** is created empty the first time.

#### Dummy files (Optionnal)

If one still wants to use the dummy files provided in the source code of the mockup, he should copy them manually.

Perform a git pull of the rs-testmeans project on the local pc and access the simulated data from the **rs-testmeans/src/adgs/config/Storage** directory.

Then simply make an archive of the files :

```shell
cd rs-testmeans/src/ADGS/config/Storage
tar -zcvf dummy_files.tgz *
```

Copy it from the source code to the desired mockup-station-adgs pod :

```shell
kubectl -n processing cp dummy_files.tgz mockup-station-adgs-6b7b9669bc-z6xjr:/opt/adgs/config/Storage/dummy_files.tgz
```

And finally uncompress the archive on the pod :

```shell
kubectl -n processing exec -ti mockup-station-adgs-6b7b9669bc-z6xjr -- bash
cd /opt/adgs/config/Storage
tar -zxvf dummy_files.tgz
```

#### Real files

Copy the files to the pod :

```shell
kubectl -n processing cp file1 mockup-station-adgs-6b7b9669bc-z6xjr:/opt/adgs/config/Storage/file1
kubectl -n processing cp file2 mockup-station-adgs-6b7b9669bc-z6xjr:/opt/adgs/config/Storage/file2
[...]
kubectl -n processing cp fileN mockup-station-adgs-6b7b9669bc-z6xjr:/opt/adgs/config/Storage/fileN
```

Note: If you have many files, you can create an archive, copy it on the pod and uncompress it on the pod with the `tar` command.

### ADGS simulator config

There are 2 configuration files managed as ConfigMap :

- Catalog/GETFileResponse.json
- auth_tmp.json

Refer to [Add data into RS testmeans ADGS simulator](#add-data-into-rs-testmeans-adgs-simulator)

To add a session or to add more files, one should :

1. Copy the files to **/opt/adgs/config/Storage/** (Done in previous steps)

2. Edit the configuration file of the **Catalog** folder :

   ```shell
   kubectl -n processing edit cm mockup-station-adgs-catalog-config
   ```

3. Restart the pod (`kubectl -n processing rollout restart mockup-station-adgs`)
