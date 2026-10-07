from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "START_ASSAULT_FIRE.ps1"
README = ROOT / "README.md"
HOSTS_SCRIPT = ROOT / "tools" / "setup" / "setup_assaultfire_hosts.ps1"


class OneClickLauncherTests(unittest.TestCase):
    def text(self, path):
        return path.read_text(encoding="utf-8", errors="replace")

    def test_one_click_entrypoint_exists(self):
        self.assertTrue(SCRIPT.is_file())

    def test_script_detects_game_beside_or_around_repo(self):
        s = self.text(SCRIPT)
        self.assertIn('TCLS\\client.exe', s)
        self.assertIn('TCLS\\Tenio\\TCLS.dll', s)
        self.assertIn('Binaries\\Win32\\TGame.exe', s)
        self.assertIn('Find-GameRoot', s)

    def test_script_bootstraps_supported_python_and_requirements(self):
        s = self.text(SCRIPT)
        self.assertIn('9NQ7512CXL7T', s)
        self.assertIn('Python Install Manager', s)
        self.assertIn('install default', s)
        self.assertIn('"requirements.txt"', s)
        self.assertIn('"-m", "venv"', s)
        self.assertIn('"pip", "install"', s)
        self.assertIn('Python 3.10+', s)

    def test_existing_supported_python_is_detected_before_winget(self):
        s = self.text(SCRIPT)
        for marker in (
            '"python.exe"',
            '"python3.exe"',
            '"python312.exe"',
            '"python3.12.exe"',
            '@("py.exe", "py")',
            '"--list-paths"',
            'Resolve-SupportedPython',
        ):
            self.assertIn(marker, s)
        self.assertLess(
            s.index('foreach ($name in @('),
            s.index('Trying Windows Package Manager (winget)'),
        )

    def test_launcher_accepts_python_310_or_newer_instead_of_exact_312(self):
        s = self.text(SCRIPT)
        self.assertIn('function Test-SupportedPythonPath', s)
        self.assertIn("sys.version_info >= (3,10) and sys.version_info < (4,0)", s)
        self.assertIn('Get-ChildItem -LiteralPath $scripts -Filter "python*.exe"', s)
        self.assertIn('Where-Object { $_.Name -notmatch "(?i)^pythonw" }', s)
        self.assertNotIn('function Test-Python312Path', s)
        self.assertNotIn('function Ensure-Python312', s)

    def test_python_install_manager_runtime_is_found_without_path_alias(self):
        s = self.text(SCRIPT)
        self.assertIn('function Find-PythonInstallManager', s)
        self.assertIn('function Find-ManagedPython', s)
        self.assertIn('list --format=exe --one 3', s)
        self.assertIn('Microsoft\\WindowsApps\\pymanager.exe', s)
        self.assertIn('Add-PythonManagerAliasesToPath', s)

    def test_manual_readme_uses_version_agnostic_python_selector(self):
        s = self.text(README)
        self.assertIn('py -3 --version', s)
        self.assertIn('py -3 -m venv .venv', s)
        self.assertNotIn('py -3.12', s)

    def test_launcher_prints_revision_for_stale_zip_diagnosis(self):
        s = self.text(SCRIPT)
        self.assertIn('2026-10-05-oneclick-v36-servermove-v4', s)
        self.assertIn('Launcher revision: $LAUNCHER_REVISION', s)

    def test_launcher_asks_before_replacing_private_key(self):
        s = self.text(SCRIPT)
        self.assertIn('Do you have your own PRIVATE.PEM here and want to keep using it?', s)
        self.assertIn('Do you have your own PRIVATE.PEM key to use?', s)
        self.assertIn('Your PRIVATE.PEM was preserved', s)
        self.assertIn('Prompt "Replace your PRIVATE.PEM and APClient.dat with a new matching pair?"', s)
        self.assertIn('-DefaultYes $false -DoNotRemember', s)
        self.assertIn('Your PRIVATE.PEM was preserved', s)
        self.assertIn('forceNewPair -or', s)

    def test_elevated_launch_helper_saves_failure_diagnostics(self):
        s = self.text(SCRIPT)
        self.assertIn('af_tgame_launch_helper.log', s)
        self.assertIn('Tee-Object -FilePath', s)
        self.assertIn('See helper log: $helperLog', s)

    def test_helper_keeps_native_python_warnings_non_fatal(self):
        s = self.text(SCRIPT)
        self.assertIn('$ErrorActionPreference = "Continue"', s)
        self.assertIn('$helperExitCode = $LASTEXITCODE', s)
        self.assertIn('$ErrorActionPreference = $savedErrorActionPreference', s)

    def test_launcher_self_elevates_before_setup(self):
        s = self.text(SCRIPT)
        self.assertIn("function Test-IsAdministrator", s)
        self.assertIn("if (-not (Test-IsAdministrator))", s)
        self.assertIn("Start-Process -FilePath $currentPowerShellExe -Verb RunAs", s)
        self.assertLess(
            s.index("Start-Process -FilePath $currentPowerShellExe -Verb RunAs"),
            s.index("Initialize-LauncherConfig"),
        )
        for switch in ("SetupOnly", "SkipPythonInstall", "KeepServer"):
            self.assertIn("if ($" + switch + ")", s)

    def test_python_launcher_default_runtime_is_accepted_when_supported(self):
        s = self.text(SCRIPT)
        self.assertIn('Python Launcher default is supported', s)
        self.assertIn('Test-SupportedPythonPath $pyLauncher.Source', s)
        self.assertIn('foreach ($minor in @(14, 13, 12, 11, 10))', s)

    def test_python_fallback_uses_latest_stable_without_minor_version_pin(self):
        s = self.text(SCRIPT)
        self.assertIn('$managerPackageId = "9NQ7512CXL7T"', s)
        self.assertIn('& $manager install default', s)
        self.assertIn('Installing the current stable Python 3 runtime...', s)
        self.assertNotIn('Python.Python.3.12', s)

    def test_manager_self_update_retries_python_runtime_install(self):
        s = self.text(SCRIPT)
        self.assertIn('for ($attempt = 1; $attempt -le 2; $attempt++)', s)
        self.assertIn('$managerUpdatedDuringInstall = $false', s)
        self.assertIn('Python install manager was successfully updated', s)
        self.assertIn(
            'if ($attempt -eq 1 -and $managerUpdatedDuringInstall)',
            s,
        )
        self.assertIn(
            'Python Install Manager updated itself; retrying runtime installation',
            s,
        )
        self.assertIn('$manager = Find-PythonInstallManager', s)

    def test_winget_output_cannot_pollute_bootstrap_python_path(self):
        s = self.text(SCRIPT)
        self.assertIn(
            '& $winget.Source install --exact --id $managerPackageId --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 |',
            s,
        )
        self.assertIn(
            'ForEach-Object { Write-Host ([string]$_) }',
            s,
        )
        self.assertRegex(
            s,
            r'& \$winget\.Source install .*?2>&1\s*\|\s*ForEach-Object\s*\{\s*Write-Host',
        )

    def test_root_level_python_install_is_detected_before_winget(self):
        s = self.text(SCRIPT)
        self.assertIn(
            r'Get-ChildItem -LiteralPath ($systemDrive + "\") -Directory -Filter "Python*"',
            s,
        )

    def test_native_command_output_cannot_pollute_return_values(self):
        s = self.text(SCRIPT)
        self.assertIn(
            '& $Exe @Arguments 2>&1 | ForEach-Object',
            s,
        )
        self.assertIn(
            'Write-Host ([string]$_)',
            s,
        )
        self.assertIn('$exitCode = $LASTEXITCODE', s)

    def test_nonstandard_venv_python_filename_is_discovered(self):
        s = self.text(SCRIPT)
        self.assertIn('function Find-VenvPython', s)
        self.assertIn(
            'Get-ChildItem -LiteralPath $scripts -Filter "python*.exe"',
            s,
        )
        self.assertIn(
            'Where-Object { $_.Name -notmatch "(?i)^pythonw" }',
            s,
        )

    def test_existing_venv_is_persistent_across_zip_updates(self):
        s = self.text(SCRIPT)
        self.assertRegex(s, r'\$venvDir\s*=\s*Join-Path\s+\$runtimeRoot\s+"venv"')
        self.assertRegex(
            s,
            r'\$legacyPersistentDir\s*=\s*Join-Path\s+\$runtimeRoot\s+"venv-py312"',
        )
        self.assertIn(
            'Reusing legacy persistent runtime',
            s,
        )
        self.assertIn(
            'Creating persistent Python environment (FIRST TIME ONLY)',
            s,
        )
        self.assertIn(
            'Preserve-BadRuntime',
            s,
        )
        self.assertNotIn(
            'Remove-Item -LiteralPath $venvDir -Recurse -Force',
            s,
        )

    def test_main_uses_game_root_persistent_runtime(self):
        s = self.text(SCRIPT)
        self.assertIn(
            'Ensure-SupportedPython $repoRoot $gameRoot',
            s,
        )
        self.assertIn(
            'Ensure-Venv $repoRoot $gameRoot $bootstrapPython',
            s,
        )

    def test_existing_dependencies_can_skip_pip_reinstall(self):
        s = self.text(SCRIPT)
        self.assertIn(
            'Existing Python dependencies verified; no pip install needed.',
            s,
        )
        self.assertIn(
            '42 <= major < 47',
            s,
        )
        self.assertIn(
            'FIRST TIME OR REQUIREMENTS CHANGED',
            s,
        )

    def test_runtime_components_inherit_the_launcher_admin_token(self):
        s = self.text(SCRIPT)
        self.assertIn(
            "The emulator server inherits this launcher's Administrator token.",
            s,
        )
        self.assertIn(
            "The TGame launch helper inherits this launcher's Administrator token.",
            s,
        )
        self.assertEqual(s.count("-Verb RunAs"), 1)
        self.assertIn("$env:AF_DS_PYTHON=", s)
        self.assertIn("patch_tcls_suspended_launch.py", s)

    def test_launcher_waits_for_flushed_tcls_readiness_before_start(self):
        s = self.text(SCRIPT)
        self.assertIn('" -u " + (Quote-PS $helper)', s)
        self.assertIn('Wait-ForTclsHelperArmed $helperLog $helperWindow 120', s)
        self.assertIn('Remove-Item -LiteralPath $helperLog -Force', s)
        self.assertIn('New-Item -ItemType File -Path $helperLog -Force', s)

    def test_elevated_command_keeps_env_variable_names_literal(self):
        s = self.text(SCRIPT)
        for name in (
            "AF_CLIENT_ROOT",
            "AF_GAME_DIR",
            "AF_DS_SPAWNER_ENABLED",
            "AF_DS_PYTHON",
        ):
            self.assertIn(
                f"'$env:{name}='",
                s,
            )
            self.assertNotIn(
                f'"$env:{name}="',
                s,
            )

    def test_launcher_path_is_initialized_before_console_helper(self):
        s = self.text(SCRIPT)
        self_match = re.search(r'\$self\s*=\s*\$MyInvocation\.MyCommand\.Path', s)
        helper_match = re.search(r'\$consoleHelper\s*=\s*Join-Path\s+\$PSScriptRoot', s)
        self.assertIsNotNone(self_match)
        self.assertIsNotNone(helper_match)
        self.assertLess(
            self_match.start(),
            helper_match.start(),
        )

    def test_console_windows_disable_quickedit_blocking(self):
        s = self.text(SCRIPT)
        helper = self.text(ROOT / "tools" / "setup" / "af_console_nonblocking.ps1")
        self.assertIn('af_console_nonblocking.ps1', s)
        self.assertGreaterEqual(
            s.count('Disable-AFConsoleBlockingSelection'),
            3,
        )
        self.assertIn('ENABLE_QUICK_EDIT_MODE = 0x0040', helper)
        self.assertIn('ENABLE_EXTENDED_FLAGS = 0x0080', helper)
        self.assertIn('mode &= ~ENABLE_QUICK_EDIT_MODE', helper)
        self.assertIn('SetConsoleMode', helper)

    def test_permanent_tcls_patch_is_prompted_and_hash_guarded(self):
        s = self.text(SCRIPT)
        self.assertIn(
            '13EAD403452E0F25CF00658369BF4BF5FF34ED1B16027F7833FB27D398386CD1',
            s,
        )
        self.assertIn(
            '3FF351E0ADB594D7544E28DB2E966A6D6EB548E9DF70DAAF4DAF58F2EE438D56',
            s,
        )
        self.assertIn('patch_tcls_apclient_raw_pem.py', s)
        self.assertIn('Patch TCLS.dll permanently', s)
        self.assertIn('Continue without patching it again?', s)
        self.assertIn('TCLS.dll is already patched. Continue without patching it again?', s)
        self.assertIn('Do you believe this TCLS.dll is already custom-patched?', s)
        self.assertIn('exact verified patched hash', s)

    def test_script_prepares_local_afdev_from_owned_tgame(self):
        s = self.text(SCRIPT)
        expected = 'B4273F2658CA94EEBC559A997FDFCD02D51E77CE75B892250C1DB7FB80C70B51'
        self.assertIn(expected, s)
        self.assertIn('TGame_AFDEV.exe', s)
        self.assertIn(
            'Copy-Item -LiteralPath $tgame -Destination $afdev -Force',
            s,
        )
        self.assertNotIn('Invoke-WebRequest', s)

    def test_script_handles_keys_hosts_server_helper_and_client(self):
        s = self.text(SCRIPT)
        for marker in (
            'generate_local_rsa_keypair.py',
            'diagnose_tcls_apclient.py',
            'setup_assaultfire_hosts.ps1',
            'assaultfire_server_v143b.py',
            'patch_tcls_suspended_launch.py',
            'AF_CLIENT_ROOT',
            'AF_GAME_DIR',
            'AF_DS_SPAWNER_ENABLED',
            'preflight_status.json',
            'Start-Process -FilePath $clientExe',
        ):
            self.assertIn(marker, s)


    def test_launcher_preferences_are_local_and_documented(self):
        s = self.text(SCRIPT)
        config_example = ROOT / "launcher.config.example.json"
        self.assertIn('launcher.config.json', s)
        self.assertIn('function Read-LauncherChoice', s)
        self.assertIn('function Get-TGameBinaryCheck', s)
        self.assertIn('tools\\patches\\tgame_binary.py', s)
        self.assertNotIn('ConfirmTGame_', s)
        self.assertTrue(config_example.is_file())
        self.assertIn('launcher.config.json', self.text(ROOT / ".gitignore"))
        self.assertIn('launcher.config.json', self.text(README))

    def test_readme_promotes_one_click_path(self):
        s = self.text(README)
        self.assertIn('Easiest way — use the one-click script', s)
        self.assertIn('START_ASSAULT_FIRE.ps1', s)
        self.assertIn('TGame_AFDEV.exe', s)
        self.assertIn('TGame.exe.bak', s)
        self.assertIn('.afdt', s)
        self.assertIn('section-header slot', s)
        self.assertNotIn('The original `TGame.exe` is not changed on disk.', s)

    def test_localized_readmes_disclose_permanent_tgame_patch_and_backup(self):
        for path in ROOT.glob("README-*.md"):
            if path.name == "README-LANGUAGES.md":
                continue
            with self.subTest(readme=path.name):
                self.assertIn("TGame.exe.bak", self.text(path))
                self.assertIn(".afdt", self.text(path))


    def test_launcher_waits_for_tcls_armed_before_prompting_for_start(self):
        s = self.text(SCRIPT)
        self.assertIn("function Wait-ForTclsHelperArmed", s)
        self.assertIn("Remove-Item -LiteralPath $helperLog", s)
        self.assertIn("TCLS ARMED", s)
        self.assertIn("if ($HelperProcess.HasExited) {", s)
        self.assertIn("Timed out after $TimeoutSeconds seconds waiting", s)
        self.assertIn("do not click START yet", s)
        self.assertIn(" -u ", s)

        client_launch = s.index("Start-Process -FilePath $clientExe")
        armed_wait = s.index("Wait-ForTclsHelperArmed $helperLog $helperWindow")
        start_instructions = s.index('Write-Title "YOU ARE DONE WITH SETUP"')
        self.assertLess(client_launch, armed_wait)
        self.assertLess(armed_wait, start_instructions)
        self.assertNotIn("Start-Sleep -Milliseconds 700", s)

    def test_hosts_helper_takes_host_ip_parameter_defaulting_to_loopback(self):
        s = self.text(HOSTS_SCRIPT)
        self.assertIn("param(", s)
        self.assertIn('[string]$HostIp = "127.0.0.1"', s)
        self.assertLess(s.index("param("), s.index('[string]$HostIp = "127.0.0.1"'))
        self.assertLess(s.index('[string]$HostIp = "127.0.0.1"'), s.index("$ErrorActionPreference"))

    def test_hosts_helper_maps_all_three_names_to_host_ip(self):
        s = self.text(HOSTS_SCRIPT)
        self.assertIn('"tversion.levelupgames.ph"   = $HostIp', s)
        self.assertRegex(s, r'"tauthproxy\.levelupgames\.ph"\s*=\s*\$HostIp')
        self.assertRegex(s, r'"tdir\.levelupgames\.ph"\s*=\s*\$HostIp')
        self.assertEqual(s.count('"127.0.0.1"'), 1)

    def test_launcher_hosts_check_takes_expected_ip(self):
        s = self.text(SCRIPT)
        self.assertIn("function Test-AFHosts([string]$ExpectedIp)", s)
        body = s[s.index("function Test-AFHosts"):s.index("function Ensure-Hosts")]
        self.assertIn("$ExpectedIp", body)
        self.assertNotIn("127.0.0.1", body)

    def test_launcher_hosts_repair_passes_expected_ip_through(self):
        s = self.text(SCRIPT)
        self.assertIn("function Ensure-Hosts([string]$RepoRoot,[string]$ExpectedIp)", s)
        body = s[s.index("function Ensure-Hosts"):s.index("function Stop-RunningGameProcesses")]
        self.assertEqual(len(re.findall(r"Test-AFHosts\s+(?:-ExpectedIp\s+)?\$ExpectedIp", body)), 2)
        self.assertIn("-File $hostScript -HostIp $ExpectedIp", body)
        self.assertNotIn("127.0.0.1", body)

    def test_launcher_main_flow_ensures_hosts_with_expected_ip(self):
        s = self.text(SCRIPT)
        call = "Ensure-Hosts $repoRoot $expectedIp"
        self.assertIn(call, s)
        self.assertEqual(s.count("Ensure-Hosts $repoRoot"), s.count(call))
        assignment = re.search(r"\$expectedIp\s*=", s)
        self.assertIsNotNone(assignment)
        self.assertLess(assignment.start(), s.index(call))

    def test_launcher_declares_remote_mode_parameters(self):
        s = self.text(SCRIPT)
        block = s[s.index("param("):s.index("function Test-IsAdministrator")]
        self.assertIn('[string]$RemoteHost = ""', block)
        self.assertIn('[string]$ApClientSha256 = ""', block)
        for switch in ("SetupOnly", "SkipPythonInstall", "KeepServer"):
            self.assertIn("[switch]$" + switch, block)
        declarations = [l.strip() for l in block.splitlines() if l.strip().startswith("[")]
        for line in declarations[:-1]:
            self.assertTrue(line.endswith(","), line)
        self.assertFalse(declarations[-1].endswith(","), declarations[-1])

    def test_launcher_forwards_remote_mode_arguments_through_elevation(self):
        s = self.text(SCRIPT)
        host = 'if ($RemoteHost) { $elevatedArguments += @("-RemoteHost", $RemoteHost) }'
        sha = 'if ($ApClientSha256) { $elevatedArguments += @("-ApClientSha256", $ApClientSha256) }'
        keep = 'if ($KeepServer) { $elevatedArguments += "-KeepServer" }'
        launch = "Start-Process -FilePath $currentPowerShellExe -Verb RunAs"
        self.assertIn(host, s)
        self.assertIn(sha, s)
        self.assertLess(s.index(keep), s.index(host))
        self.assertLess(s.index(host), s.index(launch))
        self.assertLess(s.index(sha), s.index(launch))

    def test_launcher_defines_ipv4_pattern_before_main_flow(self):
        s = self.text(SCRIPT)
        pattern = r"$IPV4_PATTERN = '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'"
        self.assertIn(pattern, s)
        self.assertEqual(s.index("$IPV4_PATTERN"), s.index(pattern))
        self.assertLess(s.index("$TCLS_PATCHED_SHA256"), s.index(pattern))
        self.assertLess(s.index(pattern), s.index('Write-Step "Closing old Assault Fire processes"'))

    def test_launcher_validates_remote_arguments_before_any_side_effect(self):
        s = self.text(SCRIPT)
        host_msg = "-RemoteHost must be an IPv4 address"
        sha_msg = "-ApClientSha256 is required with -RemoteHost"
        first_side_effect = s.index('Write-Step "Closing old Assault Fire processes"')
        self.assertIn(host_msg, s)
        self.assertIn(sha_msg, s)
        self.assertLess(s.index(host_msg), first_side_effect)
        self.assertLess(s.index(sha_msg), first_side_effect)
        self.assertRegex(s, r"-RemoteHost must be an IPv4 address[^\n]*\$RemoteHost")
        host_check = re.search(r"\$RemoteHost\s*-(?:not)?match\s*\$IPV4_PATTERN", s, re.I)
        self.assertIsNotNone(host_check)
        self.assertLess(host_check.start(), s.index(host_msg))
        self.assertLess(s.index(host_msg) - host_check.start(), 300)
        sha_check = re.search(r"\$ApClientSha256\s*-(?:not)?match\s*['\"][^'\"\n]*\{64\}", s, re.I)
        self.assertIsNotNone(sha_check)
        self.assertLess(sha_check.start(), s.index(sha_msg))
        self.assertLess(s.index(sha_msg) - sha_check.start(), 300)

    def test_launcher_maps_hosts_to_remote_host_when_given(self):
        s = self.text(SCRIPT)
        call = "Ensure-Hosts $repoRoot $expectedIp"
        assignment = re.search(r"\$expectedIp\s*=[^\n]*\$RemoteHost", s)
        self.assertIsNotNone(assignment)
        self.assertLess(assignment.end(), s.index(call))
        self.assertIsNone(
            re.search(r'\$expectedIp\s*=\s*"127\.0\.0\.1"', s[assignment.end():s.index(call)])
        )

    def test_launcher_reads_public_host_env_in_main_try_before_hosts_mapping(self):
        s = self.text(SCRIPT)
        call = s.index("Ensure-Hosts $repoRoot $expectedIp")
        main = re.search(r"\ntry\{\s*\$expectedIp", s)
        self.assertIsNotNone(main)
        for pin in ("$env:AF_PUBLIC_HOST", "AF_PUBLIC_HOST must be an IPv4 address"):
            at = s.index(pin, main.start())
            self.assertLess(at, call)
        self.assertRegex(s, r"\$env:AF_PUBLIC_HOST\)?\.Trim\(\)")
        env_at = s.index("$env:AF_PUBLIC_HOST", main.start())
        self.assertRegex(s[env_at:call], r"\$expectedIp\s*=\s*\$publicHost")

    def test_launcher_validates_public_host_env_and_names_source_and_value(self):
        s = self.text(SCRIPT)
        msg = "AF_PUBLIC_HOST must be an IPv4 address"
        self.assertRegex(s, re.escape(msg) + r"[^\n]*got '\$")
        at = s.index(msg)
        window = s[max(0, at - 400):at]
        self.assertIn("$env:AF_PUBLIC_HOST", window)
        self.assertRegex(window, r"-(?:not)?match\s*\$IPV4_PATTERN")

    def test_remote_host_wins_over_public_host_env(self):
        s = self.text(SCRIPT)
        self.assertRegex(s, r"-not\s*\$RemoteHost\s*-and[^\n]*\$env:AF_PUBLIC_HOST")

    def test_launcher_keeps_loopback_default_without_remote_host_or_public_host(self):
        s = self.text(SCRIPT)
        self.assertRegex(s, r'\ntry\{\s*\$expectedIp="127\.0\.0\.1"')

    def test_launcher_skips_key_generation_in_remote_mode(self):
        s = self.text(SCRIPT)
        guard = 'if(-not $RemoteHost){Write-Step "Preparing the local RSA/APClient pair"; Ensure-Keys $repoRoot $gameRoot $venvPython}'
        self.assertIn(guard, s)
        self.assertEqual(s.count("Ensure-Keys $repoRoot"), 1)
        self.assertLess(s.index(guard), s.index("Ensure-Hosts $repoRoot $expectedIp"))

    def test_local_server_start_is_the_else_branch_of_the_remote_check(self):
        s = self.text(SCRIPT)
        start = 'Write-Step "Starting the emulator server"'
        self.assertIn("}else{" + start, s)
        self.assertEqual(s.count(start), 1)
        self.assertIn("if($RemoteHost){", s)
        self.assertGreater(
            s.rindex("if($RemoteHost){", 0, s.index(start)),
            s.index("Ensure-Hosts $repoRoot $expectedIp"),
        )
        branch = s.rindex("if($RemoteHost){", 0, s.index(start))
        self.assertLess(s.index("if($SetupOnly){"), branch)
        self.assertLess(s.index("$env:AF_CLIENT_ROOT=$gameRoot"), branch)

    def test_remote_branch_runs_preflight_cli_without_starting_a_server(self):
        s = self.text(SCRIPT)
        start = s.index('Write-Step "Starting the emulator server"')
        remote = s[s.rindex("if($RemoteHost){", 0, start):start]
        cli = '"--remote-host",$RemoteHost,"--apclient-sha256",$ApClientSha256'
        self.assertIn(cli, s)
        self.assertIn(cli, remote)
        self.assertRegex(remote, r"&\s*\$venvPython[^\n]*assaultfire_preflight\.py[^\n]*" + re.escape(cli))
        run = remote.index(cli)
        self.assertLess(remote.index("Remove-Item -LiteralPath $statusPath"), run)
        after = remote[remote.index("$LASTEXITCODE", run):]
        self.assertIn("throw", after)
        self.assertIn("$statusPath", after)
        self.assertRegex(after, r"\$status\s*=")
        for forbidden in (
            "Start-Process",
            "[ACCOUNT]",
            "assaultfire_server_v143b.py",
            "Ensure-Keys",
            "PRIVATE.PEM",
        ):
            self.assertNotIn(forbidden, remote)

    def test_local_server_start_block_is_unchanged_inside_else_branch(self):
        s = self.text(SCRIPT)
        marker = '}else{Write-Step "Starting the emulator server"'
        self.assertIn(marker, s)
        local = s[s.index(marker):s.index('Write-Step "Starting the automatic TGame launch helper"')]
        for line in (
            "$serverWindow=Start-Process -FilePath $currentPowerShellExe -WorkingDirectory $repoRoot -PassThru",
            'Write-Host "[WAIT] Waiting for server preflight and listener gate..."; $status=Wait-ForLaunchGate $statusPath 45',
            "[ACCOUNT] First-time players must register on the local account page before signing in.",
            "[ACCOUNT] The page should open automatically. If not, copy the [WEB] Registration URL from the server window (usually http://127.0.0.1:8080/register).",
            "[ACCOUNT] Use the same username and password in the Assault Fire launcher. Register only once for this server database.",
        ):
            self.assertIn(line, local)

    def test_done_banner_hides_local_server_and_account_hints_in_remote_mode(self):
        s = self.text(SCRIPT)
        tail = s[s.index('Write-Title "YOU ARE DONE WITH SETUP"'):]
        for local in (
            'Write-Host "The emulator server is running."',
            'Write-Host "  1. First time only: register on the local account page opened in your browser."',
        ):
            self.assertIn(local, tail)
            at = tail.index(local)
            line = tail[tail.rindex("\n", 0, at) + 1:tail.index("\n", at)]
            self.assertTrue(line.lstrip().startswith("if($RemoteHost){"), line)
            self.assertIn("}else{" + local, line)
        self.assertIn("ask the host to create your account", tail)

    def test_remote_play_guide_exists_and_is_linked_from_readme(self):
        guide = ROOT / "docs" / "REMOTE_PLAY_TAILSCALE.md"
        self.assertTrue(guide.is_file(), "docs/REMOTE_PLAY_TAILSCALE.md is missing")
        s = self.text(guide)
        for phrase in (
            "tailscale ip -4",
            "AF_PUBLIC_HOST",
            "-RemoteHost",
            "-ApClientSha256",
            "Get-FileHash",
            "APClient.dat",
            "Never copy PRIVATE.PEM",
            "100.64.0.0/10",
            "9060",
            "8000",
            "9010",
            "65005",
            "65006",
            "65008-65011",
            "New-NetFirewallRule",
            "never port-forward",
            "python.exe",
            "7777",
            "subnet router",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, s)
        rules = [line for line in s.splitlines() if line.startswith("New-NetFirewallRule")]
        self.assertEqual(len(rules), 2)
        for line in rules:
            self.assertIn("-RemoteAddress 100.64.0.0/10", line)
        self.assertIn("docs/REMOTE_PLAY_TAILSCALE.md", self.text(README))


if __name__ == "__main__":
    unittest.main()
