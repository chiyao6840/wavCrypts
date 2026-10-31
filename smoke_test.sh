#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
if [ ! -x ./wavcrypt ]; then
    make || exit 1
fi
rm -rf testtmp
mkdir testtmp

pass=0
fail=0
check() {
    if [ "$1" -eq 0 ]; then
        printf 'PASS: %s\n' "$2"
        pass=$((pass+1))
    else
        printf 'FAIL: %s\n' "$2"
        fail=$((fail+1))
    fi
}

python3 - <<'PY'
import os
os.makedirs('testtmp', exist_ok=True)
open('testtmp/text.txt','wb').write(b'Hello WAV!\n' + bytes(range(256)))
open('testtmp/empty.bin','wb').write(b'')
open('testtmp/random.bin','wb').write(os.urandom(5 * 1024 * 1024 + 7))
open('testtmp/中文 文件名.bin','wb').write(os.urandom(1001))
PY

# Encrypt and decrypt regular files.
for f in text.txt empty.bin random.bin "中文 文件名.bin"; do
    src="testtmp/$f"
    wav="$src.wav"
    cp "$src" "testtmp/$f.orig"
    printf '0\n%s\ncorrect horse battery staple\ncorrect horse battery staple\n' "$src" | ./wavcrypt >testtmp/log.txt 2>&1
    rc=$?
    check "$rc" "encrypt $f"
    python3 - "$wav" <<'PY'
import sys, wave
with wave.open(sys.argv[1], 'rb') as w:
    assert w.getnchannels() == 1
    assert w.getsampwidth() == 2
    assert w.getframerate() == 44100
    assert w.getnframes() * 2 == len(w.readframes(w.getnframes()))
PY
    check "$?" "valid WAV structure $f"
    rm "$src"
    printf '1\n%s\ncorrect horse battery staple\n' "$wav" | ./wavcrypt >testtmp/log.txt 2>&1
    rc=$?
    check "$rc" "decrypt $f"
    cmp -s "$src" "testtmp/$f.orig"
    check "$?" "round-trip bytes $f"
    rm -f "$wav"
done

# Wrong password must fail without creating output.
src="testtmp/wrong.bin"
printf 'wrong-password-test-data' > "$src"
cp "$src" "$src.orig"
printf '0\n%s\nright-password-123\nright-password-123\n' "$src" | ./wavcrypt >/dev/null 2>&1
rm "$src"
printf '1\n%s\nwrong-password-123\n' "$src.wav" | ./wavcrypt >/dev/null 2>&1
rc=$?
test "$rc" -ne 0
check "$?" "wrong password rejected"
test ! -e "$src"
check "$?" "wrong password leaves no output"

# Tampered authentication tag must fail.
cp "$src.wav" testtmp/tampered.wav
python3 - <<'PY'
p='testtmp/tampered.wav'
with open(p,'r+b') as f:
    f.seek(92)
    b=f.read(1)
    f.seek(92)
    f.write(bytes([b[0]^1]))
PY
printf '1\ntesttmp/tampered.wav\nright-password-123\n' | ./wavcrypt >/dev/null 2>&1
rc=$?
test "$rc" -ne 0
check "$?" "tampered WAV rejected"
test ! -e testtmp/wrong.bin
check "$?" "tampered WAV leaves no output"

# Overwrite confirmation: answer N, then Y.
src="testtmp/overwrite.bin"
printf 'overwrite-data' > "$src"
printf '0\n%s\noverwrite-password\noverwrite-password\n' "$src" | ./wavcrypt >/dev/null 2>&1
rm "$src"
printf 'do-not-overwrite' > "$src"
printf '1\n%s\noverwrite-password\nn\n' "$src.wav" | ./wavcrypt >/dev/null 2>&1
test "$(cat "$src")" = 'do-not-overwrite'
check "$?" "overwrite N keeps existing file"
printf '1\n%s\noverwrite-password\ny\n' "$src.wav" | ./wavcrypt >/dev/null 2>&1
cmp -s "$src" <(printf 'overwrite-data')
check "$?" "overwrite Y replaces existing file"

# No temporary files left behind.
find testtmp -maxdepth 1 \( -name '.file2wav-*' -o -name '*.tmp.*' \) | grep . >/dev/null
test $? -ne 0
check "$?" "temporary files cleaned up"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
test "$fail" -eq 0
