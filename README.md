# rs-testmeans

Test means of [RS-Python](https://github.com/RS-PYTHON/rs-documentation): mockups of the external data sources and
of a DPR processor, used by the tests, by the [local mode](https://github.com/RS-PYTHON/rs-demo/blob/develop/docs/local-mode.md)
and by the test platforms.

## Overview

The mockups implement the [OData](https://www.odata.org/) interfaces of the
[Copernicus Space Component](https://sentinels.copernicus.eu/) stations, with a subset of their filters, the basic
and OAuth2 authentication, and the download of the files. They are [Flask](https://flask.palletsprojects.com/)
applications that read their catalogs and files from a configuration folder:

| Mockup | Source | Simulated station |
|---|---|---|
| CADIP | [src/CADIP](src/CADIP) | CADU Interface Delivery Point: the sessions and the raw data files (CADU chunks) of the satellites. |
| ADGS | [src/ADGS](src/ADGS) | Auxiliary Data Gathering Service (AUXIP): the auxiliary files. |
| PRIP | [src/PRIP](src/PRIP) | Production Interface Delivery Point: the Sentinel products. |
| LTA | [src/LTA](src/LTA) | Long Term Archive: the archived products. |
| DPR | [src/DPR](src/DPR) | A mockup of the EOPF processing units, packaged in a Dask image, that generates fake Zarr products from the inputs given in a payload file. It is used to test the processing flows without the real processors. |

The services of [rs-server](https://github.com/RS-PYTHON/rs-server) that access these stations are described in
[External data sources](https://github.com/RS-PYTHON/rs-server/blob/develop/docs/doc/users/external-data-sources.md).

The Docker images are published on the GitHub Container Registry:
`ghcr.io/rs-python/rs-testmeans_<station>-station-mock` (`adgs`, `cadip`, `lta`, `prip`) and
`ghcr.io/rs-python/dask/mockup/<mode>` (`local` or `k8s`) for the DPR mockup.

## Getting started

The mockups are started by the [local mode](https://github.com/RS-PYTHON/rs-demo/blob/develop/docs/local-mode.md)
of rs-demo, and deployed on the test platforms with the `mockup-*` applications of
[rs-server-deployment](https://github.com/RS-PYTHON/rs-server-deployment).

To build and run a mockup alone, e.g. the CADIP mockup:

```shell
cd src/CADIP
docker build -t cadip-station-mock .
docker run --rm -p 5000:5000 cadip-station-mock
```

The mockup listens on the port 5000 by default. Its options are `-H` (host), `-p` (port) and `-c` (configuration
folder), see [Add data to the mockups](docs/add_mockups_data.md).

## Documentation

- [Add data to the mockups](docs/add_mockups_data.md), locally and on a cluster.
- [Local mode](https://github.com/RS-PYTHON/rs-demo/blob/develop/docs/local-mode.md)
- [Coding environment](https://github.com/RS-PYTHON/rs-documentation/blob/develop/docs/developers/coding-environment.md)

## Related repositories

- [rs-server](https://github.com/RS-PYTHON/rs-server): services that access the stations.
- [rs-demo](https://github.com/RS-PYTHON/rs-demo): local mode, that runs the mockups.
- [rs-helm](https://github.com/RS-PYTHON/rs-helm), [rs-server-deployment](https://github.com/RS-PYTHON/rs-server-deployment):
  Helm charts and deployment of the mockups on a cluster.

## Contributing

See the [contribution guidelines](https://github.com/RS-PYTHON/rs-documentation/blob/develop/docs/developers/contributing.md).
Report bugs in the [issue tracker](https://github.com/RS-PYTHON/rs-testmeans/issues). In case of sensitive bugs like
security vulnerabilities, please contact <ops_coprs@airbus.com> directly instead of using the issue tracker.

## Licensing

The code in this project is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

---

![](https://raw.githubusercontent.com/RS-PYTHON/.github/refs/heads/main/profile/banner_logo.jpg)

This project is funded by the EU and ESA.
