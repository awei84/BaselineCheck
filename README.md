## 工具介绍
`BaselineCheck`采用golang开发，支持`Centos`、`Ubuntu`下基本信息收集、合规基线检查、病毒后门检测以及配合一线渗透人员进行快速应急响应；
如需长期检测配置`crontab`定时任务即可。

## 操作说明:
1. 将成功构建的脚本文件复制到需扫描的设备中;
2. 查看上述个脚本文件是否具有可执行权限,若没有可通过命令实现:`chmod -R 777 <file-name>`;
3. 查看登录设备的当前用户是否为高权限或相应权限的用户，如没有可通过命令`sudo`或者切换`root`用户实现；[确保脚本执行`root`权限]
4. 使用方式: `./baseline_linux`
5. 等待运行结束后查看`result.json`中结果存档

## 案例说明:

1. 运行

   ```bash
   `例如: ./baseline_linux
   ```