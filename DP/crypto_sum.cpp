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
} ;

using thread_info = thread_info_pristine;

pthread_mutex_t mutex_go;
int Go;
double MSE_final = 0;
int nthreads = 4;

void Computation(int n, int t, double epsilon){
	double real_sum;//真实数据求和结果
	vector<double>user_data;//用户原始数据
	vector<int>user_upload;//用户上传数据
	double c,gamma;//协议对应参数
	double MSE = 0;
	double z=0;//求和结果
	double delta = pow(2, -30);
	int k;//桶个数

	c = 14 * log(2 / delta) / epsilon / epsilon;
	k = round(pow((double)n / c, (double)1 / 3));
	gamma =(double) (k + 1) / n * c;
	default_random_engine generator(time(0));
	bernoulli_distribution b(gamma);

	srand(time(0));

	for (int j = 0; j < t; j++)
	{
		real_sum = 0;
		z = 0;
		user_data.clear();
		user_upload.clear();
		for (int i = 0; i < n; i++)
		{
			user_data.push_back(rand() / double(RAND_MAX));// 生成用户原始数据属于0 - k某个桶中,rand() / double(RAND_MAX) 生成0-1之间浮点数
			real_sum +=user_data[i];
		}
		for (int i = 0; i < n; i++)
		{
			if (b(generator))
				user_upload.push_back(rand() % (k + 1));
			else
			{
				bernoulli_distribution d(user_data[i] * k - floor(user_data[i] * k));
				user_upload.push_back(floor(user_data[i] * k) + d(generator));//用户离散化后数据
			}
			z += user_upload[i];
		}
		z = z / k;
		z = (z - gamma / 2 * n) / (1 - gamma);
		MSE += (real_sum - z)*(real_sum - z);
	}
	MSE = MSE / t;

    pthread_mutex_lock(&mutex_go); 
    MSE_final += MSE;
    Go++;
    pthread_mutex_unlock(&mutex_go);
}

void* Thread_Computation(void* arg){
    thread_info* data = static_cast<thread_info*>(arg);

    Computation(data->n,data->t,data->epsilon);

    pthread_exit(NULL);
}

void Start_Thread_Computation(int n, double epsilon, int t,int nthreads){
    std::vector<thread_info> thread_data(nthreads);
    Go = 0;

    int m_internal = ceil(((double)t)/nthreads);
    
    pthread_t* Ts = new pthread_t[nthreads];
    for(int i=0; i<nthreads; i++){
        thread_data[i].n = n;
        thread_data[i].epsilon = epsilon;
        thread_data[i].t_id = i;
        thread_data[i].t = m_internal;
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

    opt.syntax = "./crypto_sum.x [OPTIONS]\n";
    opt.example = "./crypto_sum.x \n";

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

    /*
    *	Variable Initialzation and allocation
    */
	int n = 1000;//用户人数
	int t = 100;//重复次数
	double epsilon = 1;
	double delta = pow(2, -30);

	opt.parse(argc, argv);
    string usage;
    opt.get("--number_users")->getInt(n);
    opt.get("--number_trails")->getInt(t);
    opt.get("--epsilon")->getDouble(epsilon);

    string logFile_name = "crypto_sum.log";
    ofstream logFile_out(logFile_name.c_str(),ios::app);

    logFile_out << "[*Parameters* (n, t, epsilon)] = ("<< n <<" , "<< t<<" , "<<epsilon<<")\n";
    cout << "[*Parameters* (n, t, epsilon)] = ("<< n <<" , "<< t<<" , "<<epsilon<<")\n";

	double c,gamma;//协议对应参数
	int k;

	c = 14 * log(2 / delta) / epsilon / epsilon;
	k = round(pow((double)n / c, (double)1 / 3));
	gamma =(double) (k + 1) / n * c;
	if (gamma > 1)
	{
		cout << "[*ERROR*] gamma>1" << endl;
		logFile_out << "[*ERROR*] gamma>1" << endl;
		logFile_out.close();
		return 0;
	}

	MSE_final = 0;
	Start_Thread_Computation(n,epsilon,t,nthreads);
	double MSE = MSE_final/nthreads;
	cout << "[*MSE*] = "<< MSE <<"\n\n";

	logFile_out << "[*MSE*] = "<< MSE <<"\n\n";

	logFile_out.close();
	return 0;
}