# -*- coding: utf-8 -*-
#Author: zhangguoxin 20190114
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
    print forensics_type,start_date,end_date,unit_size
    var_available_size = bundle_tarfile.collect_du_result(cmd = 'sh du_awk.sh',forensics_type='network',start_date=start_date,end_date=end_date,out_put='forensics.txt')
    print '当前/var目录可用硬盘空间: %sG' % (var_available_size/1024/1024)
    du_result_file='/tmp/network_forensics.txt'
    #du_result_file='forensics_all.txt'
    results = bundle_tarfile.get_du_result(du_result_file)
    bundle_tarfile.bundle_tar_zip(results, start_date, end_date, unit_size,debug=True,rate=1.0)