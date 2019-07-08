FROM python:3.6.8-stretch

ARG delft_repo=kermitt2/delft
ARG delft_tag=master

RUN curl --progress-bar --location \
  "https://github.com/${delft_repo}/archive/${delft_tag}.tar.gz" \
  --output "/tmp/${delft_tag}.tar.gz" \
  && tar -C "/opt" -xvf "/tmp/${delft_tag}.tar.gz" \
  && rm "/tmp/${delft_tag}.tar.gz" \
  && ln -s "/opt/delft-${delft_tag}" "/opt/delft"

WORKDIR /opt/delft

ENV PATH=/root/.local/bin:${PATH}
RUN pip install --user -r requirements.txt
RUN pip install --user -r requirements.cpu.txt

ARG install_dev
ENV PROJECT_FOLDER=/opt/sciencebeam-trainer-delft
COPY requirements.dev.txt "${PROJECT_FOLDER}/"
RUN if [ "${install_dev}" = "y" ]; then pip install -r "${PROJECT_FOLDER}/requirements.dev.txt"; fi

COPY sciencebeam_trainer_delft "${PROJECT_FOLDER}/sciencebeam_trainer_delft"
COPY setup.py "${PROJECT_FOLDER}/"

RUN ln -s "${PROJECT_FOLDER}/sciencebeam_trainer_delft" ./sciencebeam_trainer_delft \
  && ln -s /opt/delft/delft "${PROJECT_FOLDER}/delft"

COPY .flake8 .pylintrc pytest.ini "${PROJECT_FOLDER}"/
COPY tests "${PROJECT_FOLDER}/tests"
