#include<iostream>
#include<stdlib.h>
#include <time.h>
#include<random>
#include<vector>

#include "Tools/ezOptionParser.h"
#include <unistd.h>
#include <pthread.h>

using namespace std;

struct thread_info_pristine {
   int t_id;
   int n;
   double epsilon;
   int t;
   int k;
} ;

using thread_info = thread_info_pristine;

pthread_mutex_t mutex_go;
int Go;
double MSE_final = 0;
int nthreads = 4;

void Computation(int n, int t, double epsilon, int k){
	double lambda;//假设上传随机值的人数
	double z= 0;//analyzer得到的求和结果
	double delta = pow(2, -30);
	if(n < 1.0 / epsilon * log(8.0 * (double)k / delta)*sqrt(27648 * (double)k*log(4 * (double)k / delta)))
	{
		pthread_mutex_lock(&mutex_go); 
    		Go++;
    		pthread_mutex_unlock(&mutex_go);
		return;
	}
	
/*	int k = round(epsilon*pow(n,(double)1/2));//桶个数
	if (k == 0)
		k = 1;
	if (k == 0)
		k = 1;
	if (n < 1.0 / epsilon * log(8.0 * (double)k / delta)*sqrt(27648 * (double)k*log(4 * (double)k / delta)))
	{
		int k1 = 1;
		if (n < 1.0 / epsilon * log(8.0 * k1 / delta)*sqrt(27648 * k1*log(4 * k1 / delta)))
		{
			cout << "没有满足的桶数量";
			return ;
		}
		while (n> 1.0 / epsilon * log(8.0 * (double) k1 / delta)*sqrt(27648 * k1*log(4 * (double) k1 / delta)))
		{
			k = k1;
			k1 += 1;
		}
	}*/
	double MSE = 0;
	vector<double>user_data;
	vector<int>user_upload;
	double epsilon0 = epsilon / sqrt(8 * k*log2(2 / delta));
	double delta0 = delta / 2 / k;
	if (epsilon0 > sqrt((double)192 / n * log2(4 / delta0)))
		lambda = 64 / epsilon0/ epsilon0 * log2(4 / delta0);
	else lambda = n - epsilon0 * pow(n, 1.5) / sqrt(432 * log2(4 / delta0));
	default_random_engine generator(time(0));
	
	srand(time(0));
	double realsum;//真实求和结果
	int nnum;

	for (int j = 0; j < t; j++)
	{
		nnum = 0;
		realsum = 0;
		z= 0;
		user_data.clear();
		user_upload.clear();
		for (int i = 0; i < n; i++)
		{
			user_data.push_back(rand() / double(RAND_MAX));// 生成用户原始数据属于1 - k某个桶中,rand() / double(RAND_MAX) 生成0-1之间浮点数
			realsum += user_data[i];
		}

		for (int i = 0; i < n; i++)
		{
			bernoulli_distribution d(user_data[i] * k - floor(user_data[i] * k));
			user_upload.push_back(floor(user_data[i] * k) + d(generator));//用户离散化后数据
			nnum += user_upload[i];
		}
		binomial_distribution<int>b_1(nnum, lambda / 2 / n);//原始值为1的所有值的二项分布
		binomial_distribution<int>b_0(n*k - nnum, lambda / 2 / n);//原始值为0的所有值的二项分布
		z= nnum - b_1(generator)+b_0(generator);
		z= n / (n - lambda)* (z- lambda * k / 2) / k;
		MSE = MSE + (realsum - z)*(realsum - z);
	}
	MSE = MSE / t;

    pthread_mutex_lock(&mutex_go); 
    MSE_final += MSE;
    Go++;
    pthread_mutex_unlock(&mutex_go);
}

void* Thread_Computation(void* arg){
    thread_info* data = static_cast<thread_info*>(arg);

    Computation(data->n,data->t,data->epsilon,data->k);

    pthread_exit(NULL);
}

void Start_Thread_Computation(int n, double epsilon, int t,int k,int nthreads){
    std::vector<thread_info> thread_data(nthreads);
    Go = 0;

    int m_internal = ceil(((double)t)/nthreads);

    pthread_t* Ts = new pthread_t[nthreads];
    for(int i=0; i<nthreads; i++){
        thread_data[i].n = n;
        thread_data[i].epsilon = epsilon;
        thread_data[i].t_id = i;
        thread_data[i].t = m_internal;
	thread_data[i].k = k;
        pthread_create(&Ts[i], NULL,Thread_Computation, (void*) &thread_data[i]);
    }

    while(Go < nthreads){
        usleep(10);
    }

    delete Ts;
}

int main(int argc,const char **argv)
{
	ez::ezOptionParser opt;

    opt.syntax = "./Euro_real.x [OPTIONS]\n";
    opt.example = "./Euro_real.x -ndp 1 -ncp 2 -p 1 -lgp 64\n";

    opt.add(
        "1000", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of users (default: 1000)", // Help description.
        "-n", // Flag token.
        "--number_users" // Flag token.
    );
    opt.add(
        "0.5", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "epsilon (default: 0.5)", // Help description.
        "-e", // Flag token.
        "--epsilon" // Flag token.
    );
    opt.add(
            "100", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "number of trails", // Help description.
            "-t", // Flag token.
            "--number_trails" // Flag token.
    );
    opt.add(
            "1", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "number of blankets", // Help description.
            "-k", // Flag token.
            "--number_blankets" // Flag token.
    );
    /*
    *	Variable Initialzation and allocation
    */
	int n = 1000;//用户人数
	int t = 100;//重复次数
	double lambda;//假设上传随机值的人数
	double epsilon = 1;
	double delta = pow(2, -30);
	int k = round(epsilon*pow(n,(double)1/2));//桶个数
    opt.parse(argc, argv);
    string usage;
    opt.get("--number_users")->getInt(n);
    opt.get("--number_trails")->getInt(t);
    opt.get("--epsilon")->getDouble(epsilon);
    opt.get("--number_blankets")->getInt(k);

    string logFile_name = "Euro_real.log";
    ofstream logFile_out(logFile_name.c_str(),ios::app);
   

	double epsilon0 = epsilon / sqrt(8 * k*log2(2 / delta));
	double delta0 = delta / 2 / k;
	if (epsilon0 > sqrt((double)192 / n * log2(4 / delta0)))
		lambda = 64 / epsilon0/ epsilon0 * log2(4 / delta0);
	else lambda = n - epsilon0 * pow(n, 1.5) / sqrt(432 * log2(4 / delta0));
	if (lambda > n)
	{
		cout << "[*ERROR*] lambda>n\n";
		logFile_out <<  "[*ERROR*] lambda>n\n";
		logFile_out.close();
		return 0;
	}

	logFile_out << "[*Parameters* (n, t, epsilon, k)] = ("<< n <<" , "<< t<<" , "<<epsilon<<" , "<<k<<")\n";
	cout << "[*Parameters* (n, t, epsilon, k)] = ("<< n <<" , "<< t<<" , "<<epsilon<<" , "<<k<<")\n";



	MSE_final = 0;
	Start_Thread_Computation(n,epsilon,t,k,nthreads);
	if (MSE_final==0)
	{
		cout<<"数值超出限制"<<endl;
		logFile_out << "数值超出限制" <<"\n\n";
		logFile_out.close();
		return 0;
	}

	double MSE = MSE_final/nthreads;
	cout << "[*MSE*] = "<< MSE <<"\n\n";

	logFile_out << "[*MSE*] = "<< MSE <<"\n\n";

	logFile_out.close();
	return 0;
}
