FROM python:3.9

WORKDIR /app
COPY . /app

RUN useradd -ms /bin/bash user
RUN chown -R user:user /app
USER user

RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt 
# Running the script when the container launches
ENTRYPOINT ["python", "tplmap.py"]
# Default cmd
CMD ["-h"]

