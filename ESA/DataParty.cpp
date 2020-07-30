// (C) 2018 University of NKU. Free for used

/*
 * DataParty.cpp
 *
 */
#include "ESA/DataParty.h"


#include "Networking/sockets.h"
#include "Networking/ServerSocket.h"
#include "Networking/data.h"
#include "Tools/ezOptionParser.h"
#include "Exceptions/Exceptions.h"


#include <iostream>
#include <cstring>
#include <string>
#include <pthread.h>
#include <sys/time.h>
#include<stdlib.h>
#include <time.h>
#include<random>
#include<vector>

#include <farmhash.h>
#include <openssl/bio.h>
#include <openssl/buffer.h> 

#include <memory>
using BIO_MEM_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

uint64_t fmhash(std::string s, int m) {
  return util::Hash64WithSeed(s.c_str(), s.length(), m);
}

DP::DP(int argc,const char **argv)
{
    ez::ezOptionParser opt;

    opt.syntax = "./DP.x [OPTIONS]\n";
    opt.example = "./DP.x -ndp 1 -ncp 2 -p 1 -nB 200000 -uN 20000 \n";

    opt.add(
        "1", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of data parties (default: 1)", // Help description.
        "-ndp", // Flag token.
        "--number_data_parties" // Flag token.
    );
    opt.add(
        "2", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of computation parties (default: 2)", // Help description.
        "-ncp", // Flag token.
        "--number_computation_parties" // Flag token.
    );
    opt.add(
            "20000", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "number of encoders", // Help description.
            "-uN", // Flag token.
            "--number_encoders" // Flag token.
    );
    opt.add(
        "100", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "marking of the party itself (starting from 1)", // Help description.
        "-p", // Flag token.
        "--my_num" // Flag token.
    );
    opt.add(
          "-1", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Port to listen on (default: port number base - player number)", // Help description.
          "-mp", // Flag token.
          "--my-port" // Flag token.
    );
    opt.add(
          "5000", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Port number base to attempt to start connections from (default: 5000)", // Help description.
          "-pn", // Flag token.
          "--portnumbase" // Flag token.
    );
    opt.add(
          "localhost", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Host where Server.x is running to coordinate startup (default: localhost). Ignored if --ip-file-name is used.", // Help description.
          "-h", // Flag token.
          "--hostname" // Flag token.
    );
    opt.add(
            "1", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "number of the threads(default 1)", // Help description.
            "-nt", // Flag token.
            "--number_threads" // Flag token.
    );
    opt.add(
      "", // Default.
      0, // Required?
      1, // Number of args expected.
      0, // Delimiter if expecting multiple args.
      "Filename containing list of party ip addresses. Alternative to --hostname and running Server.x for startup coordination.", // Help description.
      "-ip", // Flag token.
      "--ip-file-name" // Flag token.
    );


    opt.parse(argc, argv);

    string usage;
    opt.get("--number_computation_parties")->getInt(n_computation_machines);
    opt.get("--number_data_parties")->getInt(n_data_machines);
    opt.get("--number_encoders")->getInt(uN);
    opt.get("--my_num")->getInt(mynum);
    opt.get("--my-port")->getInt(my_port);
    opt.get("--portnumbase")->getInt(PortnumBase);
    opt.get("--hostname")->getString(hostname);
    opt.get("--number_threads")->getInt(nthreads);

    if(mynum>10)
        throw runtime_error("the player number have not been set!");

    if(my_port == DP::DEFAULT_PORT){
      my_port = PortnumBase-mynum+DP::OFFSET_PORT;
    }

    if(opt.isSet("--ip-file-name")){
        opt.get("--ip-file-name")->getString(ipFileName);
    }else{
      ipFileName.clear();
    }

    // math setup
    sys = new ElGamal(n_computation_machines, PRINT);
}


void DP::start()
{

  //time measure tools 
  struct timeval t1;
  struct timeval t2;
  double cpu_time_used;

  int i;

  /* Set up the sockets */
  socket_num.resize(n_computation_machines);
  for (i=0; i<n_computation_machines; i++) { socket_num[i]=-1; }

  if(mynum ==0){
    std::cout<<"invalid data party number, must be positive!\n";
    exit(-1);
  }

  std::vector<std::string> hn(n_computation_machines); 
  if(ipFileName.size()>0){
      ifstream file(ipFileName.c_str());
      if(!file.good()){
        throw file_missing(ipFileName);
      }

      string tmp;
      for(int i=0; i<n_computation_machines; i++){
        tmp.clear();
        std::getline(file,tmp);
        hn[i] = string(tmp.c_str(), tmp.size()-1);
      }

      file.close();
  }else{
    for(int i=0; i<n_computation_machines; i++){
      hn[i] = hostname;
    }
  }

  int pn = PortnumBase+ DP::OFFSET_PORT;
  // set up connections
  for (i=0; i<n_computation_machines; i++)
  {
    cerr << "Sent " << mynum << " to " << hn[i].c_str() << ":" << pn+i << endl;
    set_up_client_socket(socket_num[i], hn[i].c_str(), pn+i);
    send(socket_num[i], (octet*)&mynum, sizeof(mynum));
    cerr << "Sent Complete " << mynum << " to " << hn[i].c_str() << ":" << pn+i << endl;
  }

  cerr << "************** Start data Collection phase **************" << endl;
  // wait until instruction to start from all computation parties
  int inst = -1;
  for (i=0; i<n_computation_machines; i++){
      while (inst != GO) 
        { 
          receive(socket_num[i], inst); 
        }
      inst = -1;
  }
  connection_active = true;
  cout << "data collection phase \n";

  gettimeofday(&t1, NULL);
  data_collection();
  gettimeofday(&t2, NULL);
  cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
  printf("data collection phase: send %d messages need  %f (ms) \n",uN,cpu_time_used);

  cpu_time_used = cpu_time_used/uN;
  printf("Local randomizer commputation time:  %f (ms) \n",cpu_time_used);



  cerr << "************** End data Collection phase **************" << endl;

  connection_active = false;
  for (int i = 0; i < n_computation_machines; i++){
    close(socket_num[i]);
  }

}

DP::~DP(){
  if(! Zq_data_table.empty()){
    int num = Zq_data_table.size();
    for(int i=0; i<num; i++){
      BN_free(Zq_data_table[i]);
    }
  }

  delete sys;
}


void DP::gen_update_data_table(std::vector<BIGNUM*>& data_table){
  
  if(!data_table.empty()){
    int num = data_table.size();
    for(int i=0; i<num; i++){
      BN_free(data_table[i]);
    }
    data_table.clear();
  }
  data_table.resize(uN);
  for(int i=0; i<uN; i++){
    data_table[i] = BN_new();
  }
//*******************data generate*************
  int n=uN;
  int k=3;
  double epsilon = 1;
  double delta = pow(2, -30);
  double gammas, gamma1, gamma2;
  gamma1 = 14 * k*log2(2 / delta) / ((n - 1)*pow(epsilon ,2));
  gamma2 = 27 * k / ((n - 1)*epsilon);
  if (gamma1 > gamma2)
    gammas = gamma1;
  else gammas = gamma2;
  std::default_random_engine generator(time(0));
  std::bernoulli_distribution b(gammas);
  srand((unsigned)time(NULL));
  std::vector<double>user_data;//local data
  std::vector<int>user_upload;//upload data
  for (int i = 0; i < n; i++)
    user_data.push_back(rand() / double(RAND_MAX));
	
  for (int i = 0; i < n; i++)
    {
      if (b(generator))
        user_upload.push_back(rand() %(k+1));
      else 
      {
        std::bernoulli_distribution d(user_data[i] * k- floor(user_data[i] * k));
        user_upload.push_back(floor(user_data[i] * k)); 
      }
    }
//*******************data generate end*************
  for(int i=0; i<uN; i++){
      BN_set_word(data_table[i],user_upload[i]);
  }
}

bool DP::data_collection(){
    bool ret = true;

    gen_update_data_table(Zq_data_table);

    ret = bucket_share_value(Zq_data_table);
    
    return ret;
}

bool DP::bucket_share_value(std::vector<BIGNUM*>& data_table){
    if(!connection_active){
          throw runtime_error("The socket has been expired");
    }

    if(data_table.size() != (unsigned int)uN){
      throw runtime_error("please generate the Zq data table first");
    }

    octetStream share_stream;

    cout<<"Warning : this part should cover in the end step, since we transfer plain there\n";
    for(int i=0; i<uN; i++){
      pack(data_table[i], share_stream);
    }

    for(int i=0; i<n_computation_machines; i++){
      send_to(i,share_stream);
    }

    return true;
}

void DP::receive_from(int i,octetStream& o,bool donthash) const{
  TimeScope ts(timer);
  o.reset_write_head();
  o.Receive(socket_num[i]);
  if (!donthash)
    { blk_SHA1_Update(&ctx,o.get_data(),o.get_length()); }
}

void DP::send_to(int i,const octetStream& o,bool donthash) const{
  TimeScope ts(timer);
  o.Send(socket_num[i]);
  if (!donthash)
      { blk_SHA1_Update(&ctx,o.get_data(),o.get_length()); }
  sent += o.get_length();
}
