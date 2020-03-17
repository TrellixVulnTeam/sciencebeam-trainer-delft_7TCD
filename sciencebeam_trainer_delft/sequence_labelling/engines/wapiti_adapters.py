import logging
import tempfile
import os
from pathlib import Path
from typing import Iterable, IO

import numpy as np

from delft.sequenceLabelling.evaluation import classification_report
from delft.sequenceLabelling.evaluation import f1_score

from sciencebeam_trainer_delft.utils.download_manager import DownloadManager
from sciencebeam_trainer_delft.utils.io import copy_file

from sciencebeam_trainer_delft.sequence_labelling.engines.wapiti import (
    WapitiModel,
    WapitiWrapper,
    format_feature_line
)


LOGGER = logging.getLogger(__name__)


class WapitiModelAdapter:
    def __init__(self, wapiti_model: WapitiModel, model_file_path: str):
        self.wapiti_model = wapiti_model
        self.model_file_path = model_file_path

    @staticmethod
    def load_from(
            model_path: str,
            download_manager: DownloadManager,
            wapiti_binary_path: str = None) -> 'WapitiModelAdapter':
        model_file_path = os.path.join(model_path, 'model.wapiti.gz')
        local_model_file_path = None
        try:
            local_model_file_path = download_manager.download_if_url(model_file_path)
        except FileNotFoundError:
            pass
        if not local_model_file_path or not os.path.isfile(str(local_model_file_path)):
            model_file_path = os.path.splitext(model_file_path)[0]
            local_model_file_path = download_manager.download_if_url(model_file_path)
        LOGGER.debug('local_model_file_path: %s', local_model_file_path)
        if local_model_file_path.endswith('.gz'):
            local_uncompressed_file_path = os.path.splitext(local_model_file_path)[0]
            copy_file(local_model_file_path, local_uncompressed_file_path, overwrite=False)
            local_model_file_path = local_uncompressed_file_path
        return WapitiModelAdapter(
            WapitiWrapper(
                wapiti_binary_path=wapiti_binary_path
            ).load_model(local_model_file_path),
            model_file_path=local_model_file_path
        )

    def _get_model_name(self) -> str:
        return os.path.basename(os.path.dirname(self.model_file_path))

    def iter_tag(self, x: np.array, features: np.array, output_format: str = None):
        assert not output_format, 'output_format not supported'
        for x_doc, f_doc in zip(x, features):
            LOGGER.debug('x_doc=%s, f_doc=%s', x_doc, f_doc)
            result = self.wapiti_model.label_features([
                [x_token] + list(f_token)
                for x_token, f_token in zip(x_doc, f_doc)
            ])
            token_and_label_pairs = [
                (x_token, result_token[-1])
                for x_token, result_token in zip(x_doc, result)
            ]
            yield token_and_label_pairs

    def tag(self, x: np.array, features: np.array, output_format: str = None):
        assert not output_format, 'output_format not supported'
        return list(self.iter_tag(x, features))

    def eval(self, x_test, y_test, features: np.array = None):
        self.eval_single(x_test, y_test, features=features)

    def eval_single(self, x_test, y_test, features: np.array = None):
        # Build the evaluator and evaluate the model
        tag_result = self.tag(x_test, features)
        y_true = [
            y_token
            for y_doc in y_test
            for y_token in y_doc
        ]
        y_pred = [
            tag_result_token[-1]
            for tag_result_doc in tag_result
            for tag_result_token in tag_result_doc
        ]

        f1 = f1_score(y_true, y_pred)
        print("\tf1 (micro): {:04.2f}".format(f1 * 100))

        report = classification_report(y_true, y_pred, digits=4)
        print(report)


def iter_doc_formatted_training_data(
        x_doc: np.array, y_doc: np.array, features_doc: np.array) -> Iterable[str]:
    for x_token, y_token, f_token in zip(x_doc, y_doc, features_doc):
        yield format_feature_line([x_token] + f_token + [y_token])
    # blank lines to mark the end of the document
    yield ''
    yield ''


def iter_formatted_training_data(
        x: np.array, y: np.array, features: np.array) -> Iterable[str]:
    return (
        line + '\n'
        for x_doc, y_doc, f_doc in zip(x, y, features)
        for line in iter_doc_formatted_training_data(x_doc, y_doc, f_doc)
    )


def write_wapiti_train_data(fp: IO, x: np.array, y: np.array, features: np.array):
    fp.writelines(iter_formatted_training_data(
        x, y, features
    ))


class WapitiModelTrainAdapter:
    def __init__(
            self,
            model_name: str,
            template_path: str,
            temp_model_path: str,
            max_epoch: str,
            download_manager: DownloadManager,
            gzip_enabled: bool = False,
            wapiti_binary_path: str = None,
            wapiti_train_args: dict = None):
        self.model_name = model_name
        self.template_path = template_path
        self.temp_model_path = temp_model_path
        self.max_epoch = max_epoch
        self.download_manager = download_manager
        self.gzip_enabled = gzip_enabled
        self.wapiti_binary_path = wapiti_binary_path
        self.wapiti_train_args = wapiti_train_args

    def train(
            self,
            x_train: np.array,
            y_train: np.array,
            x_valid: np.array = None,
            y_valid: np.array = None,
            features_train: np.array = None,
            features_valid: np.array = None):
        local_template_path = self.download_manager.download_if_url(self.template_path)
        LOGGER.info('local_template_path: %s', local_template_path)
        if not self.temp_model_path:
            self.temp_model_path = '/tmp/model.wapiti'
        with tempfile.TemporaryDirectory(suffix='wapiti') as temp_dir:
            data_path = Path(temp_dir).joinpath('train.data')
            with data_path.open(mode='w') as fp:
                write_wapiti_train_data(
                    fp, x=x_train, y=y_train, features=features_train
                )
                if x_valid is not None:
                    write_wapiti_train_data(
                        fp, x=x_valid, y=y_valid, features=features_valid
                    )
            WapitiWrapper(wapiti_binary_path=self.wapiti_binary_path).train(
                data_path=data_path,
                output_model_path=self.temp_model_path,
                template_path=local_template_path,
                max_iter=self.max_epoch,
                **(self.wapiti_train_args or {})
            )
            LOGGER.info('wapiti model trained: %s', self.temp_model_path)

    def eval(self, x_test, y_test, features: np.array = None):
        assert self.temp_model_path, "temp_model_path required"
        WapitiModelAdapter.load_from(
            os.path.dirname(self.temp_model_path),
            download_manager=self.download_manager,
            wapiti_binary_path=self.wapiti_binary_path
        ).eval(
            x_test, y_test, features=features
        )

    def save(self, output_path: str = None):
        assert output_path, "output_path required"
        assert self.temp_model_path, "temp_model_path required"
        if not Path(self.temp_model_path).exists():
            raise FileNotFoundError("temp_model_path does not exist: %s" % self.temp_model_path)
        model_file_path = os.path.join(output_path, self.model_name, 'model.wapiti')
        if self.gzip_enabled:
            model_file_path += '.gz'
        LOGGER.info('saving to %s', model_file_path)
        copy_file(self.temp_model_path, model_file_path)
