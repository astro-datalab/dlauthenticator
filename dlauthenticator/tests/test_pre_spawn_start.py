import pytest
from unittest.mock import MagicMock, patch
from tornado.concurrent import Future
from .. import dlauthenticator

user_name = "testuser"
user_uid = "666"
user_guid = "666"
user_hash = "fake-hash"
user_token = f"{user_name}:{user_uid}:{user_guid}:{user_hash}"
user_selected_profile = "big-9-gb-ram-notebook"


@pytest.fixture
def mock_spawner():
    mock_user = MagicMock()
    mock_user.name = user_name

    # Create a Future for the auth_state to be awaited
    # In Tornado, when a coroutine is yielding a value, it
    # expects that value to be a Future, or another coroutine
    # So the method mock_user.get_auth_state should return a
    # "Future", which eventually resolves to the dictionary
    # { 'token': ..., 'uid': ..., 'guid': ... }
    auth_state_future = Future()
    auth_state_future.set_result({
        'token': user_token, 'uid': user_uid, 'guid': user_guid
    })
    mock_user.get_auth_state = MagicMock(return_value=auth_state_future)

    spawner = MagicMock()
    spawner.user = mock_user
    spawner.user_options = {'profile': user_selected_profile}

    return spawner


# Run the pytest on these two classes
authenticator_classes = [
    (dlauthenticator.GCDataLabAuthenticator, {'enable_auth_state': True,
                                              'auto_login': True}),
    (dlauthenticator.GCDataLabAuthenticatorNoRedirect, {'enable_auth_state': True,
                                                        'auto_login': False}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("authenticator_class, expected_attrs", authenticator_classes)
async def test_pre_spawn_start(authenticator_class, expected_attrs, mock_spawner):
    authenticator = authenticator_class()

    assert hasattr(authenticator, 'enable_auth_state')
    assert authenticator.enable_auth_state == expected_attrs['enable_auth_state']
    assert hasattr(authenticator, 'auto_login')
    assert authenticator.auto_login == expected_attrs['auto_login']


    with patch.object(authenticator.log, 'info') as mock_log_info:
        await authenticator.pre_spawn_start(mock_spawner.user, mock_spawner)

        # Check that the log was called with the correct arguments
        mock_log_info.assert_called_once_with(
            f"user=[{mock_spawner.user.name}] NB=[{mock_spawner.user_options.get('profile')}]")

        # Check the spawner environment is set correctly
        assert mock_spawner.environment['UPSTREAM_TOKEN'] == user_token
        assert mock_spawner.environment['NB_USER'] == user_name
        assert mock_spawner.environment['NB_UID'] == user_uid
