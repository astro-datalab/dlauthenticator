# TODO

* Add other classes to test_no_bypass_file.py
* add test on invalid token
* possibly add test on valid token?

# Run pytest in a docker env
docker run -it --rm -v `pwd`/..:/local us-central1-docker.pkg.dev/data-lab-dev-01/jupyterlab-docker-repo/k8s-hub_3.1.0:1.0 /bin/bash
pip install pytest
export PATH=$PATH:/home/jovyan/.local/bin
cd /local
pytest dlauthenticator/tests/test_bypass_file.py -s -v

