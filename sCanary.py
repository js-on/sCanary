#!/usr/bin/python3
import threading
import zipfile
import glob
import zlib
import sys
import os
import re
from shutil import rmtree, get_terminal_size
import time
from glob import glob
from artifacts import *
from fingerprints import *
import json
import argparse


## Regex
msoffice_re = re.compile(rb'(http:\/\/canarytokens.(com|net)\/[a-z\/]+\/[a-z0-9]+\/\w+\.\w+)')
pdf_re = re.compile(rb'(https?:\/\/[0-9a-z]+\.canarytokens.(com|net)\/[A-Z]+)')
exe_re = re.compile(rb'(https?:\/\/[a-z0-9]+\.canarytokens.(com|net)\/any_path.\w+\?any=params\w+)')


## Constants
WIDTH = get_terminal_size().columns - 20
supported_formats = ["csv", "json"]
FORMAT = "json"
paths = []
findings = []


## structure for Canary scan info
class Canary:
    def __init__(self, path: str, ext: str, urls: list):
        self.path = path
        self.ext = ext
        self.urls = urls


## print prompt
def prompt():
    if os.name != "nt":
        print('\x1b[32m             //   ) )                                                               \n\x1b[32m    ___     //         ___       __      ___      __                \x1b[31m___            \n\x1b[32m  ((   ) ) //        //   ) ) //   ) ) //   ) ) //  ) ) //   / /  \x1b[31m//   ) ) //   / /\n\x1b[32m   \\ \\    //        //   / / //   / / //   / / //      ((___/ /  \x1b[31m//___/ / ((___/ / \n\x1b[32m//   ) ) ((____/ / ((___( ( //   / / ((___( ( //           / / \x1b[31m()/            / /  \n\n\x1b[36m                                                  (c) 2021 - Jakob Schaffarczyk\x1b[39m\n')
    else:
        print('             //   ) )                                                               \n    ___     //         ___       __      ___      __                ___            \n  ((   ) ) //        //   ) ) //   ) ) //   ) ) //  ) ) //   / /  //   ) ) //   / /\n   \\ \\    //        //   / / //   / / //   / / //      ((___/ /  //___/ / ((___/ / \n//   ) ) ((____/ / ((___( ( //   / / ((___( ( //           / / ()/            / /  \n\n                                                  (c) 2021 - Jakob Schaffarczyk\n')


## print error message
def error(msg: str):
    msg = msg.replace("\n", "\n    ")
    if os.name != "nt":
        print(f"\x1b[31m[!]\x1b[39m {msg}")
    else:
        print(f"[!] {msg}")
    sys.exit(1)


## print info message
def info(msg: str):
    msg = msg.replace("\n", "\n    ")
    if os.name != "nt":
        print(f"\x1b[32m[i]\x1b[39m {msg}")
    else:
        print(f"[i] {msg}")


## print progress bar
def progress(size: int):
    prog = round(50/size*(size-len(paths)))
    msg = f"Progress: [{prog*'#'}{(50-prog)*' '}] {size-len(paths)}/{size}"
    msg += (WIDTH-len(msg)) * ' '
    print(msg, end='\r')


## Extract MSOffice files
def extract_msoffice(fname: str, thread_id: int) -> str:
    tmpdir: str = os.path.join(os.getcwd(), f".cd_tmp{thread_id}")
    if not os.path.exists(tmpdir):
        os.mkdir(tmpdir)
    with zipfile.ZipFile(fname, 'r') as zip_ref:
        zip_ref.extractall(tmpdir)
    return tmpdir


## Analyze DOCX files
def ms_word(fname: str, thread_id: int):
    path = extract_msoffice(fname, thread_id)
    for artifact in word_artifacts:
        af: str = os.path.join(path, artifact)
        if os.path.exists(af):
            with open(af, 'rb') as md:
                metadata = md.read()
                if b"canarytokens.com" in metadata:
                    try:
                        findings.append(Canary(path=fname, ext="docx", urls=[url[0].decode("utf-8") for url in msoffice_re.findall(metadata)]))
                        rmtree(path)
                        return
                    except:
                        return


## Analyze XLSX files
def ms_excel(fname: str, thread_id: int):
    path = extract_msoffice(fname, thread_id)
    for artifact in excel_artifacts:
        af: str = os.path.join(path, artifact)
        if os.path.exists(af):
            with open(af, 'rb') as md:
                metadata = md.read()
                if b"canarytokens.com" in metadata:
                    try:
                        findings.append(Canary(path=fname, ext="xlsx", urls=[url[0].decode("utf-8") for url in msoffice_re.findall(metadata)]))
                        rmtree(path)
                        return
                    except:
                        return


## Check if MSOffice file is DOCX or EXCEL
def msoffice(fname: str, data: bytes, thread_id: int):
    for fp in docx_fingerprints:
        if fp in data:
            ms_word(fname, thread_id)
            return
    for fp in xlsx_fingerprints:
        if fp in data:
            ms_excel(fname, thread_id)
            return


## Analyze PDF files (unpack gzip compressed "payload")
def pdf(fname: str, data: bytes, thread_id: int):
    start = b">>stream"
    end = b"endstream"
    while start in data:
        data = data[data.index(start)+8:]
        extracted = data[:data.index(end)]
        try:
            decompressed = zlib.decompress(extracted.strip(b'\r\n'))
            if b"canarytoken" in decompressed:
                findings.append(Canary(path=fname, ext="pdf", urls=[url[0].decode("utf-8") for url in pdf_re.findall(decompressed)]))
        except:
            continue


## Analyze EXE files
def exe(fname: str, data: bytes, thread_id: int):
    if b"canarytoken" in data:
        findings.append(Canary(path=fname, ext="exe", urls=[url[0].decode("utf-8") for url in exe_re.findall(data)]))
        return


## Call corresponding analysis function by magic bytes
magic_bytes = {
    bytes([0x50, 0x4b, 0x03, 0x04]): msoffice,
    bytes([0x25, 0x50, 0x44, 0x46]): pdf,
    bytes([0x4d, 0x5a]): exe,
}


## Analyze bunch of files
def analyze(thread_id: int = 1, size: int = 1):
    while len(paths) != 0:
        fname = paths.pop()
        progress(size)
        try:
            with open(fname, 'rb') as fd:
                file_head = fd.read()
                for mn in magic_bytes:
                    if file_head.startswith(mn):
                        magic_bytes[mn](fname, file_head, thread_id)
        except (FileNotFoundError, OSError):
            pass


## Scan whole directory
def scan_dir(directory: str, jobs: int):
    for root, _, files in os.walk(directory):
        for name in files:
            fname = os.path.join(root, name)
            paths.append(fname)
    
    procs = []
    size = len(paths)
    info(f"Spawning {jobs} threads")
    for i in range(jobs):
        procs.append(threading.Thread(target=analyze, args=(i, size)))
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join()


## Scan single file
def scan_file(fname: str):
    paths = [fname]
    t1 = time.time()
    analyze()
    t2 = time.time()


## Print findings in requested format
def print_findings(fmt: str):
    print("\n")
    if fmt == "json":
        data = {}
        for finding in findings:
            if finding.urls:
                data[finding.path] = {
                    "extension": finding.ext,
                    "urls": finding.urls
                }
            else:
                error("[!] Something went wrong\nFailed to extract canary url from files.\nCreate an issue if needed: https://github.com/js-on/sCanary/issues")
        print(json.dumps(data, indent=4))
        return
    elif fmt == "csv":
        for finding in findings:
            if finding.urls:
                for url in finding.urls:
                    print(f"{finding.path}, {finding.ext}, {url}")
            else:
                error("[!] Something went wrong\nFailed to extract canary url from files.\nCreate an issue if needed: https://github.com/js-on/sCanary/issues")
        return


## Entry point
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--jobs", help="Number of threads to spawn", default=16, type=int)
    ap.add_argument("-o", "--format", help="Output format (json, csv)", default="json", type=str)
    ap.add_argument("-d", "--directory", help="Directory to scan", type=str)
    ap.add_argument("-f", "--file", help="File to scan", type=str)
    args = ap.parse_args(sys.argv[1:])

    if args.jobs:
        jobs = args.jobs
        
    if args.format:
        if args.format in supported_formats:
            FORMAT = args.format
        else:
            error("This format is currently not available.\nPlease file an issue at https://github.com/js-on/sCanary/issues\nor send a pull request if you've already added this format.")
    
    if args.directory:
        prompt()
        t1 = time.time()
        info(f"Starting at {time.ctime(t1)}")
        scan_dir(os.path.join(os.getcwd(), args.directory), jobs)
    elif args.file:
        prompt()
        t1 = time.time()
        info(f"Starting at {time.ctime(t1)}")
        scan_file(os.path.join(os.getcwd(), args.file))
    else:
        error("Please provide either a file (-f) or a directory (-d) to scan.\n./sCanary.py --help for more information")
    
    t2 = time.time()
    print_findings(args.format)
    print()
    info(f"Finished at {time.ctime(t2)}\nTook {round(t2-t1, 2)}s")


if __name__ == "__main__":
    main()
