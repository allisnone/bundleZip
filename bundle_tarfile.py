# -*- coding: utf-8 -*-
#Author: zhangguoxin 20190114
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

def get_partition_info(partition='/var'):
    """
    返回分区空间总共大小/G，可用空间大小/G，分区已使用率（0~1.0）
    """
    #var_available_size_cmd = "df -k %s | awk 'END {print $0}'" % partition
    partition_info_cmd = "df -k %s | awk 'END {print $2,$4,$5}'" % partition
    partition_info_1k = os.popen(partition_info_cmd).readlines()[0][:-2]
    partition_info_1k_list = partition_info_1k.split(' ')
    if len(partition_info_1k_list)==3:
        total_size_G = int(partition_info_1k_list[0])/1024/1024
        available_size_G = int(partition_info_1k_list[1])/1024/1024
        rate = int(partition_info_1k_list[2])*0.01
        return total_size_G,available_size_G,rate
    else:
        print '可能获取分区信息失败，请使用命令查看：%s' % partition_info_cmd
    return -1,-1,-1.0

def is_enough_partition(additional_size='',rate=0.9,partition='/var'):
    total_size_G,available_size_G,used_rate = get_partition_info(partition)
    if additional_size:
        additional_size_int = get_int_size(additional_size)
        if additional_size_int >=0:
            used_rate = used_rate + round(additional_size_int,2)/(total_size_G*(1024**3))
        else:
            pass
    if used_rate>rate:
        print 'ERROR: 当前tar文件保存的分区%s 以使用%s%%的空间，可用空间过小，将不进行压缩;请联系管理员清理空间或者上传已压缩的证据文件！！！'%(partition,used_rate*100)
        return False
    else:
        return True

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
    out_file = out_put
    if out_put!='forensics.txt':
        pass
    else:#默认将结果输出到/tmp目录
        out_file = '/tmp/' + forensics_type + '_' + out_put
    cmd = cmd + ' -o ' + out_file
    os.system(cmd)
    var_available_size_cmd = "df -k /var | awk 'END {print $4}'"
    var_available_size = os.popen(var_available_size_cmd).readlines()[0]
    return int(var_available_size),out_file

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
    if isinstance(size, int):
        return size
    elif size.isdigit():
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

def filter_great_dir(du_result,great_size='100M',rate=1.0,huge_rate=1.5):
    """
    过滤大文件，返回大文件和小文件两个列表
    """
    huge_dir_list = []
    great_dir_list = []
    great_size_int = get_int_size(great_size)
    normal_dir_list = []
    i = 0
    while i<len(du_result):
        #print du_result[i].split(' ')[0]
        #print get_int_size(du_result[i].split(' ')[0])
        this_dir_size = get_int_size(du_result[i].split(' ')[0])
        if this_dir_size>(great_size_int*huge_rate): #超大文件夹，一天分几个压缩包
            huge_dir_list.append(du_result[i])
        elif this_dir_size >=(great_size_int*rate): #中等文件夹，一天一个压缩包
            great_dir_list.append(du_result[i])
            #du_result.pop(i)
        else: #小文件夹
            normal_dir_list.append(du_result[i])
        i = i + 1
    return huge_dir_list,great_dir_list,normal_dir_list

def get_default_dest_dir(forensics_type='network',partition_dir='/var'):
    dest_tar_dir='/var/skyguard/sps/forensics/incident/network/'
    if forensics_type=='netword':
        pass
    elif forensics_type=='email':
        dest_tar_dir = '/var/skyguard/sps/forensics/email/'
    elif forensics_type=='endpoint':
        dest_tar_dir = '/var/skyguard/sps/forensics/incident/endpoint/'
    else:
        pass
    return dest_tar_dir,partition_dir

def tar_huge_dir(dest_dir, limit_size='10G',huge_rate=1.5,keyword='network',tar_count=0):
    """
    处理超过指定大小的文件夹情况
    """
    #['16G','/var/skyguard/sps/forensics/incident/network/2018/11/25', '2018/11/25','20181125']
    dest_tar_dir,partition_dir = get_default_dest_dir(forensics_type=keyword)
    if len(dest_dir)!=4:
        return -1
    else:
        temp_size = 0
        limit_size_int = get_int_size(limit_size)
        name_count = 0
        this_dir_size = float(dest_dir[0][:-1])
        this_dir = dest_dir[1]
        date_str = dest_dir[3]
        total_tar_count = int(this_dir_size/float(limit_size[:-1])) + 1
        print 'total_tar_count=',total_tar_count
        ls_file_cmd = "ls -altr %s | grep '^-' | awk '{print $5,$9}'" % this_dir
        all_file_info = os.popen(ls_file_cmd).readlines()
        tar_file_name = keyword +'_'  + date_str + '_%s.tar.gz'%name_count
        full_tar_file_name = os.path.join(dest_tar_dir,tar_file_name)
        tar = tarfile.open(full_tar_file_name,'w:gz')
        i = 0
        for info in all_file_info:
            file_info = info.replace('\n','').split(' ')
            #print 'file_%s: info:%s' % (i,info)
            if len(file_info)==2:
                file_size = int(file_info[0])
                file_name = file_info[1]
                if temp_size>limit_size_int: #超过限制压缩包大小，结束当前压缩，新建压缩
                    tar.close()
                    print '巨大文件分拆：%s huge_tar_count=%s 原始文件累计大小: %s, 目标tar文件: %s' % (this_dir, tar_count,temp_size,full_tar_file_name)
                    name_count = name_count + 1
                    tar_count = tar_count + 1
                    tar_file_name = keyword +'_'  + date_str + '_%s.tar.gz'%name_count
                    full_tar_file_name = os.path.join(dest_tar_dir,tar_file_name)
                    tar = tarfile.open(full_tar_file_name,'w:gz')
                    temp_size = file_size
                else:#继续累加，添加文件到压缩包
                    temp_size = temp_size + file_size
                    pass
                #print 'file:' + os.path.join(this_dir,file_name)
                #print 'temp_size: %s limit_size: %s ' % (temp_size,limit_size_int)
                #print 'simulate to add file: %s' % os.path.join(this_dir,file_name)
                #添加文件到压缩包
                tar.add(os.path.join(this_dir,file_name))
                print '添加证据文件到压缩包: ' + os.path.join(this_dir,file_name)
            else:
                print 'tar_file: file_info error: info detail: %s' % info
                pass
            i = i + 1
        tar.close()
        print '巨大文件分拆：%s huge_tar_count=%s 原始文件累计大小: %s, 目标tar文件: %s' % (this_dir, tar_count,temp_size,full_tar_file_name)
        name_count = name_count + 1
        tar_count = tar_count + 1  #下一次tar_count
        return tar_count,name_count
 
#dest_dir = ['49M', '/var/skyguard/sps/forensics/incident/network/2018/12/28', '2018/12/28', '20181228']
#tar_huge_dir(dest_dir, limit_size='10M')
def tar_and_zip_dirs(target_dirs,keyword='network',tar_cout=0):
    """
    打包和压缩文件夹列表
    target_dirs = [['2.7M', './2018/10/07', '2018/10/07', '20181007'], ['14M', './2018/10/16', '2018/10/16', '20181016'], ['8.0K', './2018/10/17', '2018/10/17', '20181017'], ['4.5M', './2018/10/18', '2018/10/18', '20181018'], ['44K', './2018/10/19', '2018/10/19', '20181019'], ['28K', './2018/10/21', '2018/10/21', '20181021'], ['208K', './2018/10/22', '2018/10/22', '20181022'], ['76K', './2018/10/23', '2018/10/23', '20181023'], ['72K', './2018/10/29', '2018/10/29', '20181029'], ['24K', './2018/10/30', '2018/10/30', '20181030'], ['13M', './2018/11/10', '2018/11/10', '20181110'], ['120K', './2018/11/13', '2018/11/13', '20181113'], ['8.0K', './2018/11/14', '2018/11/14', '20181114'], ['40K', './2018/11/15', '2018/11/15', '20181115'], ['13M', './2018/11/24', '2018/11/24', '20181124'], ['3.1M', './2018/11/25', '2018/11/25', '20181125'], ['1.1M', './2018/11/26', '2018/11/26', '20181126'], ['16M', './2018/11/27', '2018/11/27', '20181127'], ['140K', './2018/11/29', '2018/11/29', '20181129'], ['20K', './2018/11/30', '2018/11/30', '20181130'], ['116K', './2018/12/03', '2018/12/03', '20181203'], ['488K', './2018/12/18', '2018/12/18', '20181218'], ['9.6M', './2018/12/19', '2018/12/19', '20181219'], ['56K', './2018/12/20', '2018/12/20', '20181220'], ['14M', './2018/12/21', '2018/12/21', '20181221'], ['8.0K', './2018/12/22', '2018/12/22', '20181222'], ['56K', './2018/12/24', '2018/12/24', '20181224'], ['144K', './2018/12/25', '2018/12/25', '20181225'], ['20K', './2018/12/26', '2018/12/26', '20181226']]
    """
    dest_tar_dir,partition_dir = get_default_dest_dir(forensics_type=keyword)
    """
    total_size_G,available_size_G,rate = get_partition_info(partition_dir)
    if rate > limit_rate:
        print '指定分区%s大于限制-%s，放弃压缩以保持合理的可用空间！'%s (partition_dir,limit_rate)
        return -2
    """
    tar_file_name = ''
    if not target_dirs:
        print '压缩模板DIR为空，退出压缩'
        return -1
    elif len(target_dirs)==1:
        tar_file_name = keyword +'_'  + target_dirs[0][3] + '.tar.gz'
    else:
        tar_file_name = keyword +'_'  + target_dirs[0][3] +'_' + target_dirs[-1][3] + '.tar.gz'
    full_tar_file_name = os.path.join(dest_tar_dir,tar_file_name)
    if tar_cout>=0: print 'start： tar_cout=%s, target tar file: ' % tar_cout + full_tar_file_name
    tar=tarfile.open(full_tar_file_name,'w:gz')
    for target in target_dirs:
        if len(target)!=4:
            print '目标元素出错： %s' % target
            continue
        print '   添加证据文件目录: %s' % target[1]
        #添加文件夹
        tar.add(target[1])#,arcname=target[1])
    #print tar.gettarinfo().size
    if tar_cout>=0: print 'End：tar_cout=%s, target tar file: ' % tar_cout + full_tar_file_name
    tar.close()
    return 1

def bundle_tar_zip(du_results,start_date,end_date,unit_size='10M',forensics_type='network',debug=True,rate=1.0,huge_rate=1.5,buffer_rate=1.25,patition_limit_rate=0.9):
    """
    批量划分证据文件，分多次打包和压缩证据文件
    du_results = ['272M /var/skyguard/sps/forensics/incident/network/2018/11/19 2018/11/19 20181119\n']
    """
    
    huge_dir_list,great_size_list,normal_size_list = filter_great_dir(du_results, unit_size, rate)
    if debug: print '---------------------Start 单日巨大文件夹拆分压缩--------------------------------'
    huge_tar_count = 0
    for huge in huge_dir_list: #非常大的目录，拆分压缩
        huge_element = huge.replace('\n','').split(' ')
        if debug: print '开始巨大文件夹拆分压缩 , huge_tar_count=%s'% huge_tar_count
        if debug: print '被拆分文件夹： %s'% huge_element[:2]
        dir_size = get_int_size(huge_element[0])
        if not is_enough_partition(additional_size=dir_size,rate=patition_limit_rate):
            print '空间不够，后续不进行巨大文件夹分拆压缩！'
            break
        else:
            huge_tar_count, name_count = tar_huge_dir(huge_element, limit_size=unit_size,huge_rate=huge_rate,keyword=forensics_type,tar_count=huge_tar_count)
            #huge_tar_count = huge_tar_count + sub_tar_count
            if debug: print '结束巨大文件夹拆分压缩 , 拆分为%s子压缩包'% name_count
        if debug: print '-------------------------------------------------------------------'
    if debug: print '---------------------End  单日巨大文件夹拆分压缩，累计%s个巨大文件夹,共%s个压缩包--------------------------------\n' % (len(huge_dir_list),huge_tar_count)
    if debug: print '---------------------Start 单日单个大文件夹压缩--------------------------------'
    great_count = 0
    for ele in great_size_list: #先压缩大文件夹，一个文件夹压缩一次
        element = ele.replace('\n','').split(' ')
        if len(element)!=4:
            continue
        if debug: print '开始压缩单个大文件夹%s , great_count=%s'% (element[:2],great_count)
        dir_size = get_int_size(element[0])
        if not is_enough_partition(additional_size=dir_size,rate=patition_limit_rate):
            print '空间不够，后续不进行大文件夹压缩！'
            break
        else:
            tar_and_zip_dirs([element],tar_cout=great_count,keyword=forensics_type)
        if debug: print '结束压缩单个文件夹 , great_count=%s'% great_count
        if debug: print '-------------------------------------------------------------------'
        great_count = great_count + 1
    if debug: print '---------------------End 单日单个大文件夹压缩, 累计%s个大文件夹, 共%s个压缩包--------------------------------\n' % (len(great_size_list),len(great_size_list))
    if debug: print '---------------------Start 多日多个小大文件夹累计压缩--------------------------------'
    base_line = get_int_size(unit_size)
    i = 0
    temp_sum = 0 #每次压缩文件累计大小，先用于判断，后累加
    temp_sum_dir = [] #保存每次压缩文件夹列表
    is_new_start =True
    temp_start_date = '' 
    tar_count = 0
    while i < len(normal_size_list):
        #if debug: print '-------------------------------------------------------------------'
        element = normal_size_list[i].replace('\n','').split(' ')
        #print element
        #if debug: print 'i: %s, sub_dir: %s, this size: %s, sum: %s' % (i,element[2],element[0],temp_sum/1024/1024)
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
                    tar_and_zip_dirs([element],tar_cout=tar_count,keyword=forensics_type)
                    if debug: print '11 i: %s, size: %s' % (i,element[0])
                    #i = i + 1
                    #is_new_start = True
                    tar_count = tar_count + 1
                    temp_sum_dir = []
                    temp_sum = 0
                else:#多个目录，之前有累加，应该做两次压缩
                    #i 不变，保证上一个this size 小于base_line
                    #temp_sum_dir = temp_sum_dir[:-1]
                    if debug: print '22'
                    tar_and_zip_dirs(temp_sum_dir,tar_cout=tar_count,keyword=forensics_type)
                    #之前的先做一次压缩              
                    tar_and_zip_dirs([element],tar_cout=tar_count+1,keyword=forensics_type)
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
                    if debug: print '避免出现的情况，当前 i: %s, 累加的size: %sM' % (i,temp_sum/1024/1024)
                    if is_new_start: 
                        pass
                    else:#做一次压缩
                        pass
                    pass
                elif temp_sum < base_line and (temp_sum + this_size) > base_line:
                    #加上该文件夹的大小才大于baseline，上一次累加小于baseline
                    #之前的做一次压缩，并从当前开始重置
                    #if debug: print '44-'
                    if not is_enough_partition(additional_size=temp_sum,rate=patition_limit_rate):
                        print '空间不够，后续不进行目录合并压缩'
                        break
                    if (temp_sum+ this_size)<=(base_line*buffer_rate):#超出baseline在合理的范围内，一起压缩
                        if not is_enough_partition(additional_size=temp_sum+ this_size,rate=patition_limit_rate):
                            print '空间不够，后续不进行目录合并压缩'
                            break
                        temp_sum_dir.append(element)
                        tar_and_zip_dirs(temp_sum_dir,tar_cout=tar_count,keyword=forensics_type)
                        if debug: print '合并本次压缩，当前 小文件夹目录序号i: %s, 第%s次压缩包 大小: %sM' % (i,tar_count,(temp_sum+this_size)/1024/1024)
                        print '-------------------------------------------------------------------'
                        temp_sum_dir = []
                        temp_sum = 0
                    else:#超出baseline太多，只压缩前面的；本次作为下次累加的开始
                        if not is_enough_partition(additional_size=temp_sum,rate=patition_limit_rate):
                            print '空间不够，后续不进行目录合并压缩'
                            break
                        tar_and_zip_dirs(temp_sum_dir,tar_cout=tar_count,keyword=forensics_type)
                        if debug: print '压缩之前目录，当前 小文件夹目录序号i: %s, 第%s次压缩包size: %sM' % (i,tar_count,temp_sum/1024/1024)
                        print '-------------------------------------------------------------------'
                        temp_sum_dir = [element]
                        temp_sum = this_size
                    #tar_and_zip_dirs(temp_sum_dir,tar_cout=tar_count,keyword=forensics_type)
                    tar_count = tar_count + 1
                else: #继续累加
                    #if debug: print '继续累加目录，当前 i: %s, size: %sM' % (i,temp_sum/1024/1024)
                    temp_sum  = temp_sum + get_int_size(element[0])
                    temp_sum_dir.append(element)
                    is_new_start = False
                    if i == len(normal_size_list)-1:
                        if not is_enough_partition(additional_size=temp_sum,rate=patition_limit_rate):
                            print '空间不够，最后一次未压缩！'
                        else:
                            tar_and_zip_dirs(temp_sum_dir,tar_cout=tar_count,keyword=forensics_type)
                        if debug: print '最后一次压缩之前目录，当前 小文件夹目录序号i: %s, 第%s次压缩包size: %sM' % (i,tar_count,temp_sum/1024/1024)
                        print '-------------------------------------------------------------------'
                        tar_count = tar_count + 1
                    else:
                        pass
        else:
            if debug: print '获取目录元素出错，当前 i: %s, size: %sM' % (i,temp_sum/1024/1024)
            pass
        i = i + 1
    #if debug: print 'Total tar count: %s' % tar_count
    if debug: print '---------------------End 多日多个小大文件夹累计压缩--------------------------------\n'
    total_tar_count = huge_tar_count+great_count+tar_count
    print '完成日期从%s-%s 的证据文件打包压缩，总共累计%s个压缩包' % (start_date,end_date,total_tar_count)
    return total_tar_count
"""
start_date = 18640101
end_date = 18640101
unit_size = '10G'
#du_result_file='/tmp/network_forensics.txt'
du_result_file='forensics_all.txt'
results = get_du_result(du_result_file)
bundle_tar_zip(results, start_date, end_date, unit_size,debug=True,rate=1.0)
"""