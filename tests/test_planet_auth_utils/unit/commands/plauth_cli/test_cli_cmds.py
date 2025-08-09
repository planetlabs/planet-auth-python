# Copyright 2024-2025 Planet Labs PBC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest

from click.testing import CliRunner

from planet_auth_utils.commands.cli.main import cmd_plauth


@pytest.fixture(name="click_cli_runner")
def fixture_click_cli_runner():
    return CliRunner()


class TestPlauthCli:
    # Smoke tests are to insure the commands are not just exception throwing
    # and DOA when invoked.  We do not currently test all commands like this,
    # but we do check the bare minimum of making sure each command group
    # works (which should show help).  This is to insure we do not break things
    # when refactoring or updating dependencies at a distance.

    @pytest.fixture(autouse=True)
    def _setup_caplog_fixture(self, caplog):
        # Click and Pytest seem to have some bad interactions with logs and
        # unit testing that lead to "ValueError: I/O operation on closed file"
        # when commands invoke logging.  Effectively disable logging by
        # setting the level insanely high.
        self._caplog = caplog  # pylint: disable=W0201
        self._caplog.set_level(100000)

    def test_main_no_option_shows_help(self, click_cli_runner):
        result = click_cli_runner.invoke(cmd_plauth)
        assert 0 == result.exit_code
        assert "Planet authentication utility" in result.stdout

    def test_smoke_legacy(self, click_cli_runner):
        result = click_cli_runner.invoke(cmd_plauth, ["legacy"])
        assert 0 == result.exit_code

    def test_smoke_oauth(self, click_cli_runner):
        result = click_cli_runner.invoke(cmd_plauth, ["oauth"])
        assert 0 == result.exit_code

    def test_smoke_profile(self, click_cli_runner):
        result = click_cli_runner.invoke(cmd_plauth, ["profile"])
        assert 0 == result.exit_code

    def test_smoke_version(self, click_cli_runner):
        result = click_cli_runner.invoke(cmd_plauth, ["version"])
        assert 0 == result.exit_code
