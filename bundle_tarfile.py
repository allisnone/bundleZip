# -*- coding: utf-8 -*-
#Author: zhangguoxin
import os
import shutil
import subprocess
import time
import tarfile

def getdirsize(dir):
    """
    获取目录占用空间大小
得访-    """
    size = 0
    for root, dirs, files in os.walk(dir):
        size += sum([getsize(join(root, name)) for name in files])
    return size

def collect_du_result(cmd = 'sh du_awk.sh',forensics_type='network',start_date='18480101',end_date='18481229',out_put='forensics.txt'):
    #cmd= du -h max-depth=1 | awk '{if(length($2)>11) {split(substr($2,3),a,"/");b=a[1]*10000+a[2]*100+a[3];print $1,$2,substr($2,3),b}}' | sort -t " " -k 4 -n -r
    """
    通过shell脚本获取当前目录的文件和文件夹大小,返回/var分区的可用空间大小
    """
    if forensics_type in ['network','endpoint','email']:
        cmd = cmd + ' -f ' + forensics_type
    else:
        print "Forensics type error!!!"
    if start_date>19000101:
        cmd = cmd + ' -s %s' % start_date
    else:
        print "Start date empty, error or invalid!!!"
    if end_date > 19000101:
        cmd = cmd + ' -e %s' % end_date
    else:
        print "End data empty, error or invalid!!!"
    if out_put!='forensics.txt':
        cmd = cmd + ' -o ' + out_put
    else:#默认将结果输出到/tmp目录
        cmd = cmd + ' -o ' + '/tmp/' + forensics_type + '_' + out_put
    print cmd
    os.system(cmd)
    var_available_size_cmd = "df -k /var | awk 'END {print $4}'"
    var_available_size = os.popen(var_available_size_cmd).readlines()[0]
    return int(var_available_size)

def is_number(s): 
    try: 
        #float(s) 
        return float(s)
    except:
        return -1

def get_int_size(size='10M'):
    """
    存储大单位字节数转化字节
    """
    unit = 'KMGTPEZY'#['K','M','G','T','P','E','Z','Y']
    if size.isdigit():
        return int(size)
    elif is_number(size[:-1]):#size[:-1].isdigit():
        unit_index = unit.find(size[-1].upper())  
        if unit_index>=0:
            return int(float(size[:-1]) * (1024 ** (unit_index + 1 )))
        else: #1024的八次方意外的字节数
            return -1
    else:
        return -2

def get_du_result(du_result_file='/tmp/forensics_all.txt'):
    """
    读取txt文件，获取证据文件目录信息，返回列表结果
    """
    try:
        with open(du_result_file,'r') as f:
            r = f.readlines()
            f.close()
            return r
    except:
        return []

def filter_great_dir(du_result,great_size='100M',rate=1.0):
    """
    过滤大文件，返回大文件和小文件两个列表
    """
    great_dir_list = []
    great_size_int = get_int_size(great_size)
    normal_dir_list = []
    i = 0
    while i<len(du_result):
        #print du_result[i].split(' ')[0]
        #print get_int_size(du_result[i].split(' ')[0])
        if get_int_size(du_result[i].split(' ')[0])>=(great_size_int*rate):
            great_dir_list.append(du_result[i])
            #du_result.pop(i)
        else:
            normal_dir_list.append(du_result[i])
        i = i + 1
    return great_dir_list,normal_dir_list

 
def tar_and_zip(target_dirs,keyword='forensics',is_same_dir=True,root_dir='/var/skyguard/sps/forensics/incident/network/',tar_cout=0):
    """
    打包和压缩文件夹列表
    target_dirs = [['2.7M', './2018/10/07', '2018/10/07', '20181007'], ['14M', './2018/10/16', '2018/10/16', '20181016'], ['8.0K', './2018/10/17', '2018/10/17', '20181017'], ['4.5M', './2018/10/18', '2018/10/18', '20181018'], ['44K', './2018/10/19', '2018/10/19', '20181019'], ['28K', './2018/10/21', '2018/10/21', '20181021'], ['208K', './2018/10/22', '2018/10/22', '20181022'], ['76K', './2018/10/23', '2018/10/23', '20181023'], ['72K', './2018/10/29', '2018/10/29', '20181029'], ['24K', './2018/10/30', '2018/10/30', '20181030'], ['13M', './2018/11/10', '2018/11/10', '20181110'], ['120K', './2018/11/13', '2018/11/13', '20181113'], ['8.0K', './2018/11/14', '2018/11/14', '20181114'], ['40K', './2018/11/15', '2018/11/15', '20181115'], ['13M', './2018/11/24', '2018/11/24', '20181124'], ['3.1M', './2018/11/25', '2018/11/25', '20181125'], ['1.1M', './2018/11/26', '2018/11/26', '20181126'], ['16M', './2018/11/27', '2018/11/27', '20181127'], ['140K', './2018/11/29', '2018/11/29', '20181129'], ['20K', './2018/11/30', '2018/11/30', '20181130'], ['116K', './2018/12/03', '2018/12/03', '20181203'], ['488K', './2018/12/18', '2018/12/18', '20181218'], ['9.6M', './2018/12/19', '2018/12/19', '20181219'], ['56K', './2018/12/20', '2018/12/20', '20181220'], ['14M', './2018/12/21', '2018/12/21', '20181221'], ['8.0K', './2018/12/22', '2018/12/22', '20181222'], ['56K', './2018/12/24', '2018/12/24', '20181224'], ['144K', './2018/12/25', '2018/12/25', '20181225'], ['20K', './2018/12/26', '2018/12/26', '20181226']]
    """
    tar_file_name = ''
    if not target_dirs:
        return
    elif len(target_dirs)==1:
        tar_file_name = keyword +'_'  + target_dirs[0][3] + '.tar.gz'
    else:
        tar_file_name = keyword +'_'  + target_dirs[0][3] +'_' + target_dirs[-1][3] + '.tar.gz'
    full_tar_file_name = os.path.join(root_dir,tar_file_name)
    if tar_cout>=0: print 'tar_cout=%s, target tar file: ' % tar_cout + full_tar_file_name
    tar=tarfile.open(full_tar_file_name,'w:gz')
    for target in target_dirs:
        if len(target)!=4:
            continue
        tar.add(target[1])#,arcname=target[1])
    tar.close()
    return

def bundle_tar_zip(size_list,start_date,end_date,unit_size='10M',debug=True,rate=1.0):
    """
    批量划分证据文件，分多次打包和压缩证据文件
    size_list = ['272M /var/skyguard/sps/forensics/incident/network/2018/11/19 2018/11/19 20181119\n']
    """
    tar_count = 0
    great_size_list,normal_size_list = filter_great_dir(size_list, unit_size, rate)
    for ele in great_size_list: #先压缩大文件
        element = ele.replace('\n','').split(' ')
        tar_and_zip([element],tar_cout=tar_count)
        if debug: print 'Complete to tar and zip great DIR: %s' % element[:2]
        tar_count = tar_count + 1
    base_line = get_int_size(unit_size)
    i = 0
    temp_sum = 0 #每次压缩文件累计大小，先用于判断，后累加
    temp_sum_dir = [] #保存每次压缩文件夹列表
    is_new_start =True
    temp_start_date = '' 
    while i < len(normal_size_list):
        element = normal_size_list[i].replace('\n','').split(' ')
        #print element
        if debug: print 'i: %s, sub_dir: %s, this size: %s, sum: %s' % (i,element[2],element[0],temp_sum/1024/1024)
        if len(element)==4:
            this_size = get_int_size(element[0])
            """"
            if is_new_start:
                temp_start_date = element[3][:-1]
                is_new_start = False
            else:
                pass
            #temp_sum  = temp_sum + get_int_size(element[0])
            print temp_sum
            """
            if this_size> base_line:
                if is_new_start:#直接处理或者考虑把大目录划分，或者拆分单个文件
                    #仅仅一个目录
                    #做一次压缩
                    if debug: print '11'
                    tar_and_zip([element],tar_cout=tar_count)
                    if debug: print '11 i: %s, size: %s' % (i,element[0])
                    #i = i + 1
                    #is_new_start = True
                    tar_count = tar_count + 1
                    temp_sum_dir = []
                    temp_sum = 0
                else:#多个目录，之前有累加，应该做两次压缩
                    #i 不变，保证上一个this size 小于base_line
                    #temp_sum_dir = temp_sum_dir[:-1]
                    if debug: print '11'
                    tar_and_zip(temp_sum_dir,tar_cout=tar_count)
                    #之前的先做一次压缩              
                    tar_and_zip([element],tar_cout=tar_count+1)
                    #当前再做一次压缩,
                    if debug: print '22 i: %s, size: %sM' % (i,temp_sum/1024/1024)
                    #i = i + 1
                    tar_count = tar_count + 2
                    is_new_start = True
                    temp_sum_dir = []
                    temp_sum = 0
            else: #做累计计算，由累计和决定是否做压缩
                if temp_sum >=base_line: #如果之前的累计>baseline，#应避免出现的情况，不做处理
                    #之前的做一次压缩，并从当前开始重置
                    if debug: print '33 i: %s, size: %sM' % (i,temp_sum/1024/1024)
                    if is_new_start: 
                        pass
                    else:#做一次压缩
                        pass
                    pass
                elif temp_sum < base_line and (temp_sum + this_size) > base_line:
                    #加上该文件夹的大小才大于baseline，上一次累加小于baseline
                    #之前的做一次压缩，并从当前开始重置
                    if debug: print '44-55'
                    tar_and_zip(temp_sum_dir,tar_cout=tar_count)
                    tar_count = tar_count + 1
                    if is_new_start:#仅一个文件夹，压缩
                        #i = i + 1
                        #is_new_start = True
                        if debug: print '44 i: %s, size: %s ' % (i,temp_sum/1024/1024)
                        temp_sum_dir = []
                        temp_sum = 0
                        pass
                    else:#多个文件夹，压缩
                        #tar_and_zip(temp_sum_dir)
                        #i = i + 1
                        if debug: print '55 i: %s, size: %sM' % (i,temp_sum/1024/1024)
                        is_new_start = True
                        temp_sum_dir = [element]
                        temp_sum = this_size
                else: #继续累加
                    temp_sum  = temp_sum + get_int_size(element[0])
                    temp_sum_dir.append(element)
                    is_new_start = False
                    if i == len(normal_size_list)-1:
                        if debug: print 'Final tar, i: %s, size: %sM' % (i,temp_sum/1024/1024)
                        tar_and_zip(temp_sum_dir,tar_cout=tar_count)
                        tar_count = tar_count + 1
        else:
            print 'error'
            #pass
        i = i + 1
    if debug: print 'Total tar count: %s' % tar_count
    return
"""    
#print get_int_size('12m')
var_available_size = collect_du_result(cmd = 'sh du_awk.sh',forensics_type='network',start_date='18480101',end_date='18481229',out_put='forensics.txt')
print var_available_size
print '%sG' % (var_available_size/1024/1024)
du_result_file='/tmp/network_forensics.txt'
#du_result_file='forensics_all.txt'
results = get_du_result(du_result_file)
#print results
unit_size = '500M'
#get_int_size(unit_size)
#great_dir_list,du_result = filter_great_dir(results,unit_size,rate=0.9)
#print great_dir_list
#print du_result
start_date = ''
end_date = ''
a= '89.2'

#target_dirs = [['2.7M', './2018/10/07', '2018/10/07', '20181007'], ['14M', './2018/10/16', '2018/10/16', '20181016'], ['8.0K', './2018/10/17', '2018/10/17', '20181017'], ['4.5M', './2018/10/18', '2018/10/18', '20181018'], ['44K', './2018/10/19', '2018/10/19', '20181019'], ['28K', './2018/10/21', '2018/10/21', '20181021'], ['208K', './2018/10/22', '2018/10/22', '20181022'], ['76K', './2018/10/23', '2018/10/23', '20181023'], ['72K', './2018/10/29', '2018/10/29', '20181029'], ['24K', './2018/10/30', '2018/10/30', '20181030'], ['13M', './2018/11/10', '2018/11/10', '20181110'], ['120K', './2018/11/13', '2018/11/13', '20181113'], ['8.0K', './2018/11/14', '2018/11/14', '20181114'], ['40K', './2018/11/15', '2018/11/15', '20181115'], ['13M', './2018/11/24', '2018/11/24', '20181124'], ['3.1M', './2018/11/25', '2018/11/25', '20181125'], ['1.1M', './2018/11/26', '2018/11/26', '20181126'], ['16M', './2018/11/27', '2018/11/27', '20181127'], ['140K', './2018/11/29', '2018/11/29', '20181129'], ['20K', './2018/11/30', '2018/11/30', '20181130'], ['116K', './2018/12/03', '2018/12/03', '20181203'], ['488K', './2018/12/18', '2018/12/18', '20181218'], ['9.6M', './2018/12/19', '2018/12/19', '20181219'], ['56K', './2018/12/20', '2018/12/20', '20181220'], ['14M', './2018/12/21', '2018/12/21', '20181221'], ['8.0K', './2018/12/22', '2018/12/22', '20181222'], ['56K', './2018/12/24', '2018/12/24', '20181224'], ['144K', './2018/12/25', '2018/12/25', '20181225'], ['20K', './2018/12/26', '2018/12/26', '20181226']]
#tar_and_zip(target_dirs)
#bundle_tar_zip(results, start_date, end_date, unit_size,debug=True,rate=1.0)
"""