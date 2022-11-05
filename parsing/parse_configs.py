from http.client import CONFLICT
import xml.etree.ElementTree as ET
from lxml import etree
from pathlib import Path

CONFIG_FILE = 'configs.xml'
NAMESPACE = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'


def main():
    tree = None
    with open(CONFIG_FILE, 'r') as f:
        data = f.read()
        tree = ET.fromstring(data.encode('utf-16-be'))

    print('[*] Parsing XML')

    for child in tree:
        actions = child.find(f'.//{NAMESPACE}Actions')
        
        # only tasks that execute as system
        if actions.attrib['Context'] not in ['LocalSystem', 'System']:
            continue
        
        #try:
        #    # tasks that execute binaries
        #    if not actions.find(f'.//{NAMESPACE}Exec').find(f'.//{NAMESPACE}Command').text.endswith('.exe'):
        #        continue
        #except:
        #    continue
        
        #if len(actions.find(f'.//{NAMESPACE}Exec')) > 1:
        #    cmd = actions.find(f'.//{NAMESPACE}Exec').find(f'.//{NAMESPACE}Command').text + ' ' + actions.find(f'.//{NAMESPACE}Exec').find(f'.//{NAMESPACE}Arguments').text
        #else:
        #    cmd = actions.find(f'.//{NAMESPACE}Exec').find(f'.//{NAMESPACE}Command').text
        
        taskpath = child.find(f'.//{NAMESPACE}URI').text #child[0][1].text

        #print(f'\n[+] Task URI: {taskpath}')
        #print(f'[+] Exec: {cmd}')

        #print(f'"{taskpath}","{cmd}"')
        print(f'"{taskpath}"')
                



if __name__ == '__main__':
    main()