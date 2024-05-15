import argparse
import hashlib


def generate_hash(input_string, hash_type):
    input_bytes = input_string.encode('utf-8')

    if hash_type == 'md5':
        hash_result = hashlib.md5(input_bytes).hexdigest()

    elif hash_type == 'sha1':
        hash_result = hashlib.sha1(input_bytes).hexdigest()

    elif hash_type == 'sha256':
        hash_result = hashlib.sha256(input_bytes).hexdigest()

    elif hash_type == 'blake1':
        hash_result = hashlib.blake2b(input_bytes).hexdigest()

    else:
        raise ValueError("Invalid hash type. Choose from given options: 'md5', 'sha1', 'sha256', 'blake1'.")

    return hash_result


def main():
    parser = argparse.ArgumentParser(description='Generate either MD5, SHA1, SHA256 or BLAKE2B hash from given string.')
    parser.add_argument('input_string', type=str, help='The string to generate hash from')
    parser.add_argument('hash_type', choices=['md5', 'sha1', 'sha256', 'blake1'],
                        help='The hash type to use (md5, sha1, sha256, blake1')

    args = parser.parse_args()
    input_string = args.input_string
    hash_type = args.hash_type

    try:
        hash_result = generate_hash(input_string, hash_type)
        print(f"{hash_type.upper()} Hash:", hash_result)
    except ValueError as e:
        print(e)


if __name__ == "__main__":
    main()
