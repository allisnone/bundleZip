# -*- coding: utf-8 -*-
import bundle_tarfile
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manual to this script') 
    parser.add_argument('--forensics', type=str, default = 'network') 
    parser.add_argument('--start-date', type=int, default=18640101)
    parser.add_argument('--end-date', type=int, default=18640101)
    parser.add_argument('--unit-size', type=str, default='500M')  
    args = parser.parse_args()
    forensics_type = args.forensics
    start_date = args.start_date
    end_date = args.end_date
    unit_size = args.unit_size
    unit_size = '500M'
    #print get_int_size('12m')
    print forensics_type,start_date,end_date,unit_size
    var_available_size = bundle_tarfile.collect_du_result(cmd = 'sh du_awk.sh',forensics_type='network',start_date=start_date,end_date=end_date,out_put='forensics.txt')
    print var_available_size
    print '当前/var目录可用硬盘空间: %sG' % (var_available_size/1024/1024)
    
    #print results
    #get_int_size(unit_size)
    #great_dir_list,du_result = filter_great_dir(results,unit_size,rate=0.9)
    #print great_dir_list
    #print du_result
    start_date = ''
    end_date = ''
    a= '89.2'
    
    #target_dirs = [['2.7M', './2018/10/07', '2018/10/07', '20181007'], ['14M', './2018/10/16', '2018/10/16', '20181016'], ['8.0K', './2018/10/17', '2018/10/17', '20181017'], ['4.5M', './2018/10/18', '2018/10/18', '20181018'], ['44K', './2018/10/19', '2018/10/19', '20181019'], ['28K', './2018/10/21', '2018/10/21', '20181021'], ['208K', './2018/10/22', '2018/10/22', '20181022'], ['76K', './2018/10/23', '2018/10/23', '20181023'], ['72K', './2018/10/29', '2018/10/29', '20181029'], ['24K', './2018/10/30', '2018/10/30', '20181030'], ['13M', './2018/11/10', '2018/11/10', '20181110'], ['120K', './2018/11/13', '2018/11/13', '20181113'], ['8.0K', './2018/11/14', '2018/11/14', '20181114'], ['40K', './2018/11/15', '2018/11/15', '20181115'], ['13M', './2018/11/24', '2018/11/24', '20181124'], ['3.1M', './2018/11/25', '2018/11/25', '20181125'], ['1.1M', './2018/11/26', '2018/11/26', '20181126'], ['16M', './2018/11/27', '2018/11/27', '20181127'], ['140K', './2018/11/29', '2018/11/29', '20181129'], ['20K', './2018/11/30', '2018/11/30', '20181130'], ['116K', './2018/12/03', '2018/12/03', '20181203'], ['488K', './2018/12/18', '2018/12/18', '20181218'], ['9.6M', './2018/12/19', '2018/12/19', '20181219'], ['56K', './2018/12/20', '2018/12/20', '20181220'], ['14M', './2018/12/21', '2018/12/21', '20181221'], ['8.0K', './2018/12/22', '2018/12/22', '20181222'], ['56K', './2018/12/24', '2018/12/24', '20181224'], ['144K', './2018/12/25', '2018/12/25', '20181225'], ['20K', './2018/12/26', '2018/12/26', '20181226']]
    #tar_and_zip(target_dirs)
    #bundle_tarfile.collect_du_result(cmd = 'sh du_awk.sh',forensics_type='network',start_date='18480101',end_date='18481229',out_put='forensics.txt')
    du_result_file='/tmp/network_forensics.txt'
    #du_result_file='forensics_all.txt'
    results = bundle_tarfile.get_du_result(du_result_file)
    bundle_tarfile.bundle_tar_zip(results, start_date, end_date, unit_size,debug=True,rate=1.0)