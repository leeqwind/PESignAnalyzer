"""Package a tagged analyzer and smoke-test its extracted archive."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variant', choices=('openssl', 'native'), default='openssl')
    args = parser.parse_args()
    source, build, output = (p.resolve() for p in (args.source, args.build, args.output))
    tag = os.environ['RELEASE_TAG']
    platform = os.environ['PACKAGE_PLATFORM']
    commit = os.environ['SOURCE_COMMIT']
    if not re.fullmatch(r'v[0-9][0-9A-Za-z._+-]*', tag):
        raise ValueError('Invalid version tag')
    if platform not in ('windows-x64', 'windows-x86', 'linux-x64', 'macos-arm64'):
        raise ValueError('Unknown package platform')
    native = args.variant == 'native'
    if native and not platform.startswith('windows-'):
        raise ValueError('The native CryptoAPI analyzer requires Windows')
    product = 'PESignAnalyzer' if native else 'PESignAnalyzerOpenSSL'
    project = source if native else source / 'openssl'
    version = re.search(rf'project\({product} VERSION ([0-9.]+)',
                        (project / 'CMakeLists.txt').read_text()).group(1)
    name = f'{product}-{tag}-{platform}'
    windows = platform.startswith('windows-')
    executable = product + ('.exe' if windows else '')
    binary = build / 'Release' / executable if windows else build / executable
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / name
        root.mkdir()
        shutil.copy2(binary, root / executable)
        shutil.copy2(source / 'LICENSE', root / 'LICENSE')
        if native:
            shutil.copy2(source / 'README.md', root / 'README.md')
            shutil.copy2(source / 'README.zh.md', root / 'README.zh.md')
            requirements = ('Windows x64/x86 as named. Native Windows CryptoAPI analyzer; '
                            'MSVC runtime statically linked. No OpenSSL or curl required.')
        else:
            shutil.copy2(project / 'README.md', root / 'README.zh.md')
        if windows and not native:
            # vcpkg static triplets and /MT avoid external DLL/VC Runtime requirements.
            share = Path(os.environ['VCPKG_INSTALLATION_ROOT']) / 'installed' / os.environ['VCPKG_TRIPLET'] / 'share'
            for license_file in share.glob('*/copyright'):
                destination = root / 'licenses' / license_file.parent.name
                destination.mkdir(parents=True, exist_ok=True)
                shutil.copy2(license_file, destination / 'copyright')
            if not (root / 'licenses/openssl/copyright').is_file():
                raise RuntimeError('Missing dependency licenses')
            requirements = 'Windows x64/x86 as named; dependencies and MSVC runtime statically linked.'
        elif platform.startswith('macos-'):
            run('dylibbundler', '-b', '-cd', '-x', str(root / executable),
                '-d', str(root / 'lib'), '-p', '@executable_path/lib/')
            # Include Homebrew dependency licences alongside the redistributed dylibs.
            for formula in run('brew', 'list', '--formula').splitlines():
                prefix = Path(run('brew', '--prefix', formula))
                files = [p for p in prefix.rglob('*') if p.is_file()
                         and re.match(r'(?i)^(license|licence|copying|copyright)', p.name)]
                for index, license_file in enumerate(files):
                    destination = root / 'licenses' / formula / f'{index}-{license_file.name}'
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(license_file, destination)
            for library in (root / 'lib').glob('*.dylib'):
                run('codesign', '--force', '--sign', '-', str(library))
            run('codesign', '--force', '--sign', '-', str(root / executable))
            for image in [root / executable, *(root / 'lib').glob('*.dylib')]:
                dependencies = run('otool', '-L', str(image))
                if '/opt/homebrew/' in dependencies or '/usr/local/' in dependencies:
                    raise RuntimeError(f'Unbundled Homebrew dependency: {dependencies}')
            requirements = 'macOS 15+ arm64 (Apple Silicon). Non-system dylibs included. Ad-hoc signed, not notarized.'
        elif not windows:
            requirements = ('Linux x64, Ubuntu 24.04+ (glibc 2.39+). Install runtime dependencies:\n'
                            '  sudo apt-get install libssl3t64 libcurl4t64 ca-certificates\n'
                            'OpenSSL/libcurl use system packages and are not bundled.')
        metadata = {'tag': tag, 'commit': commit, 'product': product, 'analyzer_version': version,
                    'platform': platform, 'requirements': requirements}
        if not native:
            metadata['openssl_analyzer_version'] = version
        (root / 'BUILD-INFO.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
        (root / 'README.txt').write_text(
            f'{product} {version}\nRelease: {tag}\nSource commit: {commit}\n\n'
            f'{requirements}\n\nExtract the whole archive, then run:\n'
            f'  {executable if windows else "./" + executable} --help\n'
            f'  {executable if windows else "./" + executable} '
            f'{"--verify" if native else "--json"} sample.exe\n\n'
            'See README.zh.md for usage and LICENSE / licenses for licensing.\n', encoding='utf-8')
        if windows:
            archive = output / f'{name}.zip'
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
                for path in sorted(root.rglob('*')):
                    if path.is_file():
                        package.write(path, path.relative_to(root.parent))
        else:
            archive = output / f'{name}.tar.gz'
            with tarfile.open(archive, 'w:gz') as package:
                package.add(root, arcname=name)
        extracted = Path(temp) / 'extracted'
        if windows:
            with zipfile.ZipFile(archive) as package:
                package.extractall(extracted)
        else:
            with tarfile.open(archive) as package:
                package.extractall(extracted, filter='data')
        installed = extracted / name / executable
        run(str(installed), '--help')
        reported_version = run(str(installed), '--version')
        if version not in reported_version:
            raise RuntimeError(f'Unexpected packaged version: {reported_version}')
        if native:
            run(shutil.which('pwsh') or 'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(source / 'tests/smoke.ps1'), '-Executable', str(installed))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_name(archive.name + '.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
        print(f'Packaged and tested {archive.name}: {reported_version}')


if __name__ == '__main__':
    main()
