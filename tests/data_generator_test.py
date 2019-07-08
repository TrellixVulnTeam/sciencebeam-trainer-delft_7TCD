import logging
from unittest.mock import MagicMock
from typing import List

import pytest

import numpy as np

from delft.sequenceLabelling.preprocess import to_casing_single

from sciencebeam_trainer_delft.data_generator import (
    left_pad_batch_values,
    DataGenerator
)


LOGGER = logging.getLogger(__name__)


# Note: don't use numerics in words due to num_norm flag
WORD_1 = 'word_a'
WORD_2 = 'word_b'

SENTENCE_TOKENS_1 = [WORD_1, WORD_2]

LONG_SENTENCE_TOKENS = SENTENCE_TOKENS_1 + SENTENCE_TOKENS_1 + SENTENCE_TOKENS_1
SHORT_SENTENCE_TOKENS = SENTENCE_TOKENS_1

WORD_FEATURES_1 = ('feature1-1', 'feature1-2')
WORD_FEATURES_2 = ('feature2-1', 'feature2-2')

FEATURE_MAP = {
    WORD_FEATURES_1: np.asarray([1, 0, 0, 1]),
    WORD_FEATURES_2: np.asarray([2, 0, 0, 2])
}

SENTENCE_FEATURES_1 = [WORD_FEATURES_1, WORD_FEATURES_2]

LABEL_1 = 'label1'
LABEL_2 = 'label2'

EMBEDDING_MAP = {
    WORD_1: [1, 1, 1],
    WORD_2: [2, 2, 2]
}


WORD_INDEX_MAP = {
    WORD_1: 1,
    WORD_2: 2
}


LABEL_INDEX_MAP = {
    LABEL_1: 1,
    LABEL_2: 2
}


DEFAULT_ARGS = dict(
    batch_size=1,
    tokenize=False,
    shuffle=False
)


def get_word_vector(word: str):
    return np.asarray(EMBEDDING_MAP[word])


def get_word_vectors(words: List[str]):
    return np.stack([get_word_vector(word) for word in words])


def get_word_indices(words: List[str]):
    return np.asarray([WORD_INDEX_MAP[word] for word in words])


def get_label_indices(labels: List[str]):
    return np.asarray([LABEL_INDEX_MAP[label] for label in labels])


def get_transformed_feature(word_features: str):
    return np.asarray(FEATURE_MAP[tuple(word_features)])


def get_transformed_features(sentence_features: List[str]):
    return np.stack([get_transformed_feature(feature) for feature in sentence_features])


def preprocess_transform(X, y=None, extend=False):
    assert not extend
    x_words_transformed = [get_word_indices(sentence_tokens) for sentence_tokens in X]
    x_lengths_transformed = [len(sentence_tokens) for sentence_tokens in X]
    LOGGER.debug('x_lengths_transformed: %s', x_lengths_transformed)
    if y is None:
        return x_words_transformed, x_lengths_transformed
    y_transformed = [get_label_indices(sentence_labels) for sentence_labels in y]
    return (x_words_transformed, x_lengths_transformed), y_transformed


def preprocess_transform_features(features_batch):
    return np.asarray([get_transformed_features(features) for features in features_batch])


def get_lengths(a):
    return [len(x) for x in a]


@pytest.fixture(name='preprocessor')
def _preprocessor():
    preprocessor = MagicMock(name='preprocessor')
    preprocessor.return_casing = False
    preprocessor.return_lengths = False
    preprocessor.return_features = False
    preprocessor.transform.side_effect = preprocess_transform
    preprocessor.transform_features.side_effect = preprocess_transform_features
    return preprocessor


@pytest.fixture(name='embeddings')
def _embeddings():
    embeddings = MagicMock(name='embeddings')
    embeddings.get_word_vector.side_effect = get_word_vector
    embeddings.use_ELMo = False
    embeddings.use_BERT = False
    embeddings.embed_size = len(get_word_vector(WORD_1))
    return embeddings


def all_close(a, b):
    LOGGER.debug('a: %s', a)
    LOGGER.debug('b: %s', b)
    return np.allclose(a, b)


class TestLeftPadBatchValues:
    def test_should_left_pad_values(self):
        all_close(
            left_pad_batch_values(
                np.asarray([
                    [[1, 1], [2, 2]],
                    [[1, 1]]
                ]),
                2,
                dtype='float32'
            ), np.asarray([
                [[1, 1], [2, 2]],
                [[1, 1], [0, 0]]
            ])
        )

    def test_should_truncate_values(self):
        all_close(
            left_pad_batch_values(
                np.asarray([
                    [[1, 1], [2, 2], [3, 3]],
                    [[1, 1]]
                ]),
                2,
                dtype='float32'
            ), np.asarray([
                [[1, 1], [2, 2]],
                [[1, 1], [0, 0]]
            ])
        )


class TestDataGenerator:
    def test_should_be_able_to_instantiate(self, preprocessor, embeddings):
        DataGenerator(
            np.asarray([[WORD_1, WORD_2]]),
            np.asarray([[LABEL_1]]),
            preprocessor=preprocessor,
            embeddings=embeddings,
            **DEFAULT_ARGS
        )

    def test_should_be_able_to_get_item(self, preprocessor, embeddings):
        item = DataGenerator(
            np.asarray([SENTENCE_TOKENS_1]),
            np.asarray([[LABEL_1]]),
            preprocessor=preprocessor,
            embeddings=embeddings,
            **DEFAULT_ARGS
        )[0]
        LOGGER.debug('item: %s', item)
        assert len(item) == 2
        x, labels = item
        assert all_close(labels, get_label_indices([LABEL_1]))
        assert all_close(x[0], get_word_vectors(SENTENCE_TOKENS_1))
        assert all_close(x[1], [get_word_indices(SENTENCE_TOKENS_1)])
        assert all_close(x[-1], [len(SENTENCE_TOKENS_1)])

    def test_should_return_casing(self, preprocessor, embeddings):
        preprocessor.return_casing = True
        item = DataGenerator(
            np.asarray([SENTENCE_TOKENS_1]),
            np.asarray([[LABEL_1]]),
            preprocessor=preprocessor,
            embeddings=embeddings,
            **DEFAULT_ARGS
        )[0]
        LOGGER.debug('item: %s', item)
        assert len(item) == 2
        x, labels = item
        assert all_close(labels, get_label_indices([LABEL_1]))
        assert all_close(x[0], get_word_vectors(SENTENCE_TOKENS_1))
        assert all_close(x[1], [get_word_indices(SENTENCE_TOKENS_1)])
        assert all_close(x[2], [
            to_casing_single(SENTENCE_TOKENS_1, maxlen=len(SENTENCE_TOKENS_1))
        ])
        assert all_close(x[-1], [len(SENTENCE_TOKENS_1)])

    def test_should_return_features(self, preprocessor, embeddings):
        preprocessor.return_features = True
        item = DataGenerator(
            np.asarray([SENTENCE_TOKENS_1]),
            np.asarray([[LABEL_1]]),
            features=np.asarray([SENTENCE_FEATURES_1]),
            preprocessor=preprocessor,
            embeddings=embeddings,
            **DEFAULT_ARGS
        )[0]
        LOGGER.debug('item: %s', item)
        assert len(item) == 2
        x, labels = item
        assert all_close(labels, get_label_indices([LABEL_1]))
        assert all_close(x[0], get_word_vectors(SENTENCE_TOKENS_1))
        assert all_close(x[1], [get_word_indices(SENTENCE_TOKENS_1)])
        assert all_close(x[2], [get_transformed_features(SENTENCE_FEATURES_1)])
        assert all_close(x[-1], [len(SENTENCE_TOKENS_1)])

    def test_should_return_left_pad_batch_values(self, preprocessor, embeddings):
        preprocessor.return_features = True
        batch_size = 2
        batch = DataGenerator(
            np.asarray([
                LONG_SENTENCE_TOKENS,
                SHORT_SENTENCE_TOKENS
            ]),
            np.asarray([
                [LABEL_1] * len(LONG_SENTENCE_TOKENS),
                [LABEL_2] * len(SHORT_SENTENCE_TOKENS)
            ]),
            features=np.asarray([
                np.asarray([WORD_FEATURES_1] * len(LONG_SENTENCE_TOKENS)),
                np.asarray([WORD_FEATURES_2] * len(SHORT_SENTENCE_TOKENS))
            ]),
            preprocessor=preprocessor,
            embeddings=embeddings,
            **{
                **DEFAULT_ARGS,
                'batch_size': batch_size
            }
        )[0]
        LOGGER.debug('batch: %s', batch)
        assert len(batch) == 2
        inputs, _ = batch
        batch_x = inputs[0]
        batch_features = inputs[2]
        assert get_lengths(batch_x) == [len(LONG_SENTENCE_TOKENS)] * batch_size
        assert get_lengths(batch_features) == [len(LONG_SENTENCE_TOKENS)] * batch_size

    def test_should_not_fail_on_shuffle_dataset(self, preprocessor, embeddings):
        data_generator = DataGenerator(
            np.asarray([SENTENCE_TOKENS_1]),
            np.asarray([[LABEL_1]]),
            features=np.asarray([SENTENCE_FEATURES_1]),
            preprocessor=preprocessor,
            embeddings=embeddings,
            **DEFAULT_ARGS
        )
        data_generator._shuffle_dataset()  # pylint: disable=protected-access
