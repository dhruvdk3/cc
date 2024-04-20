# sso_cloud
This is the implementation of sso using docker with the help of flask.
We can run it locally as we run other codes.

###Docker
First we have to bulid the docker image.
```bash
docker build -t app . 
```

To run the docker image:

```bash
docker run -p 5001:5001 app
```
