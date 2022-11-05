from xml.etree import ElementTree as ET

class XMLHandler:
    NAMESPACE = 'http://schemas.microsoft.com/windows/2004/02/mit/task'

    def __init__(self, xml=None):
        ET.register_namespace('', XMLHandler.NAMESPACE)
        if xml is None:
            xml = ET.fromstring(TASK_XML_TEMPLATE)
        else:
            xml = ET.fromstring(xml)
        self.root = xml

    
    def set_command(self, command):
        self.root.find(f'.//{{{XMLHandler.NAMESPACE}}}Command').text = command

    
    def set_arguments(self, args):
        self.root.find(f'.//{{{XMLHandler.NAMESPACE}}}Arguments').text = args

    
    def set_principal_user(self):
        prin = self.root.find(f'.//{{{XMLHandler.NAMESPACE}}}Principal')
        for child in list(prin):
            prin.remove(child)

        group_id = ET.Element('GroupId')
        group_id.text = 'S-1-5-32-545'
        run_level = ET.Element('RunLevel')
        run_level.text = 'HighestAvailable'

        prin.append(group_id)
        prin.append(run_level)


    def get_xml_as_string(self):
        return ET.tostring(self.root, encoding='unicode', method='xml')


TASK_XML_TEMPLATE = '''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers />
  <Principals>
    <Principal id="Author">
      <UserId>NT AUTHORITY\System</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>P30D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command></Command>
      <Arguments></Arguments>
    </Exec>
  </Actions>
</Task>'''