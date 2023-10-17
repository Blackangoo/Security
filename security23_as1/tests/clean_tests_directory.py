import os

def clean_tests_directory():
    directory = 'tests/'

    # List of files to preserve
    files_to_preserve = ['Examples.txt', 'SecretImage.jpg', 'SecretProgram.exe', 'SecretText.txt', 'clean_tests_directory.py']

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) and filename not in files_to_preserve:
            try:
                os.remove(file_path)
                print(f"Removed file: {file_path}")
            except Exception as e:
                print(f"Error deleting file: {file_path} - {e}")

if __name__ == '__main__':
    clean_tests_directory()
