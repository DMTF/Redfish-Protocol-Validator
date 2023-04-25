# Copyright Notice:
# Copyright 2020-2022 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Protocol-Validator/blob/main/LICENSE.md

import html as html_mod
import json
from datetime import datetime

from redfish_protocol_validator import redfish_logo
from redfish_protocol_validator.constants import Result
from redfish_protocol_validator.system_under_test import SystemUnderTest

html_template = """
<html>
  <head>
    <title>Redfish Protocol Validator Test Summary</title>
    <style>
      .pass {{background-color:#99EE99}}
      .fail {{background-color:#EE9999}}
      .warn {{background-color:#EEEE99}}
      .bluebg {{background-color:#BDD6EE}}
      .button {{padding: 12px; display: inline-block}}
      .center {{text-align:center;}}
      .left {{text-align:left;}}
      .log {{text-align:left; white-space:pre-wrap; word-wrap:break-word;
             font-size:smaller}}
      .title {{background-color:#DDDDDD; border: 1pt solid; font-height: 30px;
               padding: 8px}}
      .titlesub {{padding: 8px}}
      .titlerow {{border: 2pt solid}}
      .headingrow {{border: 2pt solid; text-align:left;
                    background-color:beige;}}
      .results {{transition: visibility 0s, opacity 0.5s linear; display: none;
                 opacity: 0}}
      .resultsShow {{display: block; opacity: 1}}
      body {{background-color:lightgrey; border: 1pt solid; text-align:center;
             margin-left:auto; margin-right:auto}}
      th {{text-align:center; background-color:beige; border: 1pt solid}}
      td {{text-align:left; background-color:white; border: 1pt solid;
           word-wrap:break-word;}}
      table {{width:90%; margin: 0px auto; table-layout:fixed;}}
      .titletable {{width:100%}}
    </style>
  </head>
  <table>
    <tr>
      <th>
        <h2>##### Redfish Protocol Validator Test Report #####</h2>
        <h4><img align=\"center\" alt=\"DMTF Redfish Logo\" height=\"203\"
            width=\"288\" src=\"data:image/gif;base64,{}\"></h4>
        <h4><a href=\"https://github.com/DMTF/Redfish-Prptocol-Validator\">
            https://github.com/DMTF/Redfish-Protocol-Validator</a></h4>
        Tool Version: {}<br/>
        {}<br/><br/>
        This tool is provided and maintained by the DMTF. For feedback, please
        open issues<br/> in the tool's Github repository:
        <a href=\"https://github.com/DMTF/Redfish-Protocol-Validator/issues\">
            https://github.com/DMTF/Redfish-Protocol-Validator/issues</a><br/>
      </th>
    </tr>
    <tr>
      <th>
        System: {}/redfish/v1/, User: {}, Password: {}<br/>
        Product: {}<br/>
        Manufacturer: {}, Model: {}, Firmware version: {}<br/>
      </th>
    </tr>
    <tr>
      <td>
        <center><b>Results Summary</b></center>
        <center>Pass: {}, Warning: {}, Fail: {}, Not tested: {}</center>
      </td>
    </tr>
    {}
  </table>
</html>
"""

section_header_html = """
  <table>
    <tr>
      <th class=\"titlerow bluebg\">
        <b>{}</b>
      </th>
    </tr>
  </table>
"""

sections = [
    ('PROTO_', 'Protocol Details'),
    ('REQ_', 'Service Requests'),
    ('RESP_', 'Service Responses'),
    ('SERV_', 'Service Details'),
    ('SEC_', 'Security Details'),
]


def report_name(time, ext):
    prefix = 'RedfishProtocolValidationReport'
    name = prefix + datetime.strftime(time, '_%m_%d_%Y_%H%M%S.' + ext)
    return name


def tsv_report(sut: SystemUnderTest, report_dir, time):
    file = report_dir / report_name(time, 'tsv')
    with open(str(file), 'w', encoding='utf-8') as fd:
        header = ('Assertion\tMethod\tStatus code\tURI\tResult\tMessage\t'
                  'Requirement\n')
        fd.write(header)
        for prefix, _ in sections:
            for assertion, results in sorted(
                    sut.results.items(), key=lambda x: x[0].name):
                if not assertion.name.startswith(prefix):
                    continue
                for r in results:
                    line = '{}\t{}\t{}\t{}\t{}\t{}\t{}\n'.format(
                        assertion.name, r['method'], r['status'], r['uri'],
                        r['result'].name, r['msg'], assertion.value)
                    fd.write(line)
    return str(file)


def html_report(sut: SystemUnderTest, report_dir, time, tool_version):
    file = report_dir / report_name(time, 'html')
    html = ''
    for prefix, section_name in sections:
        html += section_header_html.format(section_name)
        for assertion, results in sorted(
                sut.results.items(), key=lambda x: x[0].name):
            if not assertion.name.startswith(prefix):
                continue
            html += '<table>'
            html += ('<th colspan="5" class="headingrow">{}: "{}"</th>'
                     .format(assertion.name, assertion.value))
            html += ('<tr><td><b>{}</b></td><td><b>{}</b></td>'
                     '<td><b>{}</b></td><td><b>{}</b></td>'
                     '<td><b>{}</b></td></tr>'
                     .format('Result', 'Method', 'Status code', 'URI',
                             'Message'))
            for r in results:
                result_class = ''
                if r['result'] == Result.PASS:
                    result_class = 'class="pass"'
                elif r['result'] == Result.WARN:
                    result_class = 'class="warn"'
                elif r['result'] == Result.FAIL:
                    result_class = 'class="fail"'
                html += ('<tr><td {}>{}</td><td>{}</td><td>{}</td>'
                         '<td>{}</td><td>{}</td></tr>'
                         .format(result_class, r['result'].name, r['method'],
                                 r['status'], r['uri'],
                                 html_mod.escape(r['msg'])))
            html += '</table>'
    with open(str(file), 'w', encoding='utf-8') as fd:
        fd.write(html_template.format(redfish_logo.logo, tool_version,
                                      time.strftime('%c'), sut.rhost,
                                      sut.username, '********',
                                      sut.product, sut.manufacturer,
                                      sut.model, sut.firmware_version,
                                      sut.summary_count(Result.PASS),
                                      sut.summary_count(Result.WARN),
                                      sut.summary_count(Result.FAIL),
                                      sut.summary_count(Result.NOT_TESTED),
                                      html))
    return str(file)


def json_results(sut: SystemUnderTest, report_dir, time, tool_version):
    file = report_dir / 'results.json'
    results = {
        'ToolName': 'Redfish-Protocol-Validator v%s' % tool_version,
        'Timestamp': {
            'DateTime': '{:%Y-%m-%dT%H:%M:%S%Z}'.format(time)
        },
        'Service': {
            'BaseURL': sut.rhost,
            'Manufacturer': sut.manufacturer,
            'Product': sut.product,
            'Model': sut.model,
            'FirmwareVersion': sut.firmware_version
        },
        'TestResults': {
            'Protocol Validations': {
                'pass': sut.summary_count(Result.PASS),
                'fail': sut.summary_count(Result.FAIL),
                'skip': sut.summary_count(Result.NOT_TESTED),
                'warn': sut.summary_count(Result.WARN)
            },
            'ErrorMessages': []
        }
    }
    with open(str(file), 'w', encoding='utf-8') as fd:
        json.dump(results, fd, indent=4)
