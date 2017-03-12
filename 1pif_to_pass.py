"""
This file is part of 1Password_to_pass.

1Password_to_pass is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

1Password_to_pass is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with 1Password_to_pass. If not, see <http://www.gnu.org/licenses/>.

src: https://github.com/cimermanGregor/1Password_to_pass
"""

import csv
import json
import os
from collections import defaultdict


def read_csv(filename="data.txt"):
    reader = csv.reader(open(filename), delimiter="\t")
    columns = reader.next()
    col_type = filter(lambda (_, v): v == "Type",
                      enumerate(columns))[0][0]
    col_title = filter(lambda (_, v): v == "Title",
                       enumerate(columns))[0][0]
    col_password = filter(lambda (_, v): v == "Password",
                          enumerate(columns))[0][0]
    # col_username = filter(lambda (_, v): v == "Username",
    #                       enumerate(columns))[0][0]
    # col_tags = filter(lambda (_, v): v == "Tags", enumerate(columns))[0][0]
    folder = "i"
    normal = 0
    wot = 0
    wot_list = []
    for i, v in enumerate(reader):
        if len(v) != len(columns):
            wot += 1
            wot_list.append(v)
            continue
        normal += 1
        title = v[col_title].replace(" ", "")
        path = "%s/%s/%s" % (folder, v[col_type][0], title)
        secure = "%s\n%s\n" % (v[col_password],
                               "\n".join(filter(lambda x: x != "", v)))
        os.system("printf \"%s\" | pass insert -m %s" % (secure, path))
    print "Normal %d, WOT? %d" % (normal, wot)
    json.dump(wot_list, open("wot.json", "w"), indent=2)


def fields_to_dict(fields, key_name="name", value_name="value"):
    return {f[key_name].lower() if key_name in f else "":
            f[value_name] if value_name in f else ""
            for f in fields}


def format_dicts(data, title=None):
    string = ""
    if title:
        string += title + "\n"
    string += "\n".join(["%20s | %-20s" % (k, v)
                         for k, v in data.items()])
    string += "\n----------------------------\n"
    return string


def save_to_pass(path, secure_string):
    secure_string = secure_string.encode('ascii', 'ignore')
    os.system("printf \"%s\" \"%s\"  | pass insert -m %s" %
              ("%s", secure_string, path))


def read_1pif(filename="data.1pif", dry_run=False, debug=False):
    lines = map(lambda line: json.loads(line),
                filter(lambda line: line[0] == "{",
                       open(filename).readlines()))
    lines_stats = defaultdict(int)
    paths = []
    for line in lines:
        lines_stats[line["typeName"]] += 1
    for line in lines:
        secure_string = ""
        title = line["title"].replace(" ", "").encode('ascii', 'ignore')
        sc = line["secureContents"]
        username = sc["username"] if "username" in sc else None
        password = sc["password"] if "password" in sc else None
        if "fields" in sc:
            fields = fields_to_dict(sc["fields"])
            secure_string += format_dicts(fields)
            if not username and "username" in fields:
                username = fields["username"]
            elif not username and "login" in fields:
                username = fields["login"]
            elif not username and "email" in fields:
                username = fields["email"]
            if not password and "password" in fields:
                password = fields["password"]
        if not password:
            password = "\n"
        secure_string = "" + password + "\n" + secure_string
        if "sections" in sc:
            for section in sc["sections"]:
                secure_string += section["title"] + "\n"
                if "fields" in section:
                    secure_string += format_dicts(
                        fields_to_dict(section["fields"],
                                       key_name="t",
                                       value_name="v"))
        if "URLs" in sc:
            urls = fields_to_dict(sc["URLs"],
                                  key_name="label",
                                  value_name="url")
            secure_string += format_dicts(urls, title="URLs")
        if "notesPlain" in sc:
            secure_string += sc["notesPlain"]
        item_type = line["typeName"] if "typeName" in line else "other.Other"
        item_type = item_type.split(".")[1][0]
        path = "i/" + item_type + "/" + title
        # solve duplicates
        if path in paths:
            path += "_" + str(line["createdAt"])
        paths += [path]
        # catch dry run
        if dry_run:
            print "Password to be added: %s" % path
            if debug:
                print "Path: %-40s | Title: %-40s | \n%s" % \
                      (path, title, secure_string)
                print "Raw: %s" % json.dumps(line, indent=4)
        else:
            save_to_pass(path, secure_string)


def main():
    read_1pif(filename="data.1pif", dry_run=True)

if __name__ == "__main__":
    main()
