"""Create and verify frame/audio stego videos from the bundled test clip.

Run from the repository root with ``python -m scripts.try_video``.
The RSA keys are disposable and exist only for this demo run.
"""

import argparse
from pathlib import Path

from stego import bootstrap_span, encode_video, generate_rsa_keypair, verify_video


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "samples" / "video-test-source.mkv"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "samples" / "video-test-output"


def main() -> None:
    """Encode, verify, and retain MKV outputs for the selected video modes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="video cover with an audio track")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="directory for stego MKV files")
    parser.add_argument("--mode", choices=("frames", "audio", "both"), default="both")
    parser.add_argument("--message", default="Hello from the video steganography demo.")
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"input video does not exist: {args.input}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    signing_private_key, sender_public_key = generate_rsa_keypair()
    receiver_private_key, receiver_public_key = generate_rsa_keypair()
    start_unit = bootstrap_span(receiver_public_key)
    message = args.message.encode("utf-8")
    modes = ("frames", "audio") if args.mode == "both" else (args.mode,)

    print(f"Cover: {args.input}")
    for mode in modes:
        output = args.output_dir / f"stego-{mode}.mkv"
        encode_video(
            args.input,
            output,
            signing_private_key,
            receiver_public_key,
            start_unit,
            3,
            message,
            b"demo=video",
            mode=mode,
        )
        result = verify_video(output, sender_public_key, receiver_private_key, mode=mode)
        if not result.valid or result.payload is None or result.payload.user_payload != message:
            raise RuntimeError(f"{mode} verification failed: {result.verdict} ({result.detail})")
        print(f"{mode}: {result.verdict}; recovered {result.payload.user_payload!r}")
        print(f"  Saved: {output}")


if __name__ == "__main__":
    main()
