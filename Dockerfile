FROM python:3-onbuild

# Add any necessary python packages
ADD requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Copy our files across
ADD ./code /code
WORKDIR /code

# Run our python script in the container
CMD [ "python", "./gt02_tracker.py"]
