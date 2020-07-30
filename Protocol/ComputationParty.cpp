// (C) 2020 University of NKU. Free for used

/*
 * ComputationParty.cpp
 *
 */
#include "Protocol/ComputationParty.h"

#include "Math/Share.h"
#include "Math/bigint.h"
#include "Auth/fake-stuff.h"
#include "Tools/ezOptionParser.h"
#include "Exceptions/Exceptions.h"

#include "Tools/octetStream.h"
#include "Tools/int.h"


#include <vector>
#include <array>
#include <numeric>
#include <sstream>
#include <math.h>  

#include <sys/time.h>

typedef struct CP_thread_sender {
   CP* obj;
   octetStream* o;
   int t_id;
   int player_no;
    bool send_func;
} thread_sender_info;


CP::CP(int argc, const char** argv)
{
    ez::ezOptionParser opt;

    opt.syntax = "./CP.x [OPTIONS]\n";
    opt.example = "./CP.x -lgp 64 -np 2 -p 0 -x 4 -ndp 1 \n";
    opt.add(
        "2", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of aggregators (default: 2)", // Help description.
        "-np", // Flag token.
        "--number_parties" // Flag token.
    );
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
        "100", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of the party (starting from 0)", // Help description.
        "-p", // Flag token.
        "--my_num" // Flag token.
    );
    opt.add(
        "128", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Bit length of GF(p) field (default: 128)", // Help description.
        "-lgp", // Flag token.
        "--lgp" // Flag token.
    );
    opt.add(
        "40", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "security parameter (default: 40)", // Help description.
        "-sec", // Flag token.
        "--security-parameter" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Directory containing the data (default: " PREP_DIR "<nparties>-<lgp>-<lg2>", // Help description.
            "-d", // Flag token.
            "--dir" // Flag token.
    );
    opt.add(
          "", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Port to listen on (default: port number base + player number)", // Help description.
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
          "Host where Server.x is running to coordinate startup (default: localhost).", // Help description.
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
            "1", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "number of buckets of histogram", // Help description.
            "-oM", // Flag token.
            "--number_buckets" // Flag token.
    );
    opt.add(
            "10000", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "number of encoders", // Help description.
            "-uN", // Flag token.
            "--number_encoders" // Flag token.
    );
    opt.add(
        "1", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "whether in local network environment, 0 means not and 1 means true", // Help description.
        "-lan", // Flag token.
        "--in lan envs" // Flag token.
    );




    opt.parse(argc, argv);

    string usage;
    string hostname;
    int in_local_envs;
    opt.get("--my_num")->getInt(mynum);
    opt.get("--lgp")->getInt(lgp);
    opt.get("--number_parties")->getInt(nparties);
    opt.get("--number_data_parties")->getInt(ndparties);
    opt.get("--portnumbase")->getInt(pnbase);
    opt.get("--hostname")->getString(hostname);
    opt.get("--number_buckets")->getInt(oM);
    opt.get("--number_encoders")->getInt(uN);
    opt.get("--number_threads")->getInt(nthreads);
    opt.get("--security-parameter")->getInt(sec);
    opt.get("--in lan envs")->getInt(in_local_envs);

    local_envs = bool(in_local_envs);
    
    if(mynum){
        playerone = false;
    }else{
        playerone = true;
    }
    tau = lgp - sec;     // sec = 40

    if(mynum>10)
        throw runtime_error("the player number have not been set!");
    if (opt.isSet("--dir"))
    {
        opt.get("--dir")->getString(PREP_DATA_PREFIX);
        PREP_DATA_PREFIX += "/";
    }
    else
        PREP_DATA_PREFIX = get_prep_dir(nparties, lgp, 40);


    ez::OptionGroup* mp_opt = opt.get("--my-port");
    if (mp_opt->isSet)
      mp_opt->getInt(my_port);
    else
      my_port = Names::DEFAULT_PORT;


    CommsecKeysPackage *keys = NULL;
    vector<Names> playerNames(nthreads*communication_multiplier);
    // // ******************************** Network Part ***********************************
    for(int i=0; i<nthreads*communication_multiplier; i++){
        playerNames[i].init(mynum, pnbase+port_increase*i, my_port, hostname.c_str());
        playerNames[i].set_keys(keys);
    }
    

    // ******************************** File Handler  ************************************
    read_setup(PREP_DATA_PREFIX);
    dataF = new Data_Files(mynum, nparties, PREP_DATA_PREFIX);
    init_offline_data();
    init_wait_to_check_buffer();

    // ******************************** Mac Key ************************************
    /* Find number players and MAC keys etc*/
    char filename[1024];
    gfp pp; 
    keyp.assign_zero();
    alphai.assign_zero();
    int N=1;
    ifstream inpf;
    for (int i= 0; i < nparties; i++)
    {
        sprintf(filename, (PREP_DATA_PREFIX + "Player-MAC-Keys-P%d").c_str(), i);
        inpf.open(filename);
        if (inpf.fail()) { throw file_error(filename); }
        inpf >> N;
        pp.input(inpf,true);
        //cout << " Key " << i << "\t p: " << pp  << endl;
        keyp.add(pp);
        inpf.close();
        if(i==mynum)
            alphai.add(pp);
    }
    //cout << "--------------\n";
    //cout << "Final Keys :\t p: " << keyp << endl;

    // p2p whole connected
    //player = new Player(playerNames[0], 0);
    thread_player.resize(nthreads*communication_multiplier);
    commu_timer.resize(nparties*nthreads*communication_multiplier);
    for(int i=0; i<nthreads*communication_multiplier; i++){
        thread_player[i] = new Player(playerNames[i], 0);
    }
    player = thread_player[0];
    CP_sockets.resize(nthreads*communication_multiplier);
    for(int i=0; i<nthreads*communication_multiplier; i++){
        CP_sockets[i].resize(nparties);
        for(int k=0; k<nparties; k++){
            CP_sockets[i][k] = thread_player[i]->socket(k);
        }
    }


    //******************************** Data Collection Phase *****************************
    DP_connector dp_handle;
    dp_handle.init(mynum, pnbase, my_port,ndparties);
    dp_handle.key_init(alphai,keyp);
    dp_handle.player_init(player);
    dp_handle.n_threads_init(nthreads);
    dp_handle.params_ofs_init(oM, uN);


    share_histogram.resize(oM);
    dp_handle.start(dataF,share_histogram);

    // multithread 
    mutex_go = PTHREAD_MUTEX_INITIALIZER;
    local_Go.resize(nthreads);
    mutex_local_go.resize(nthreads);
    for(int i=0; i<nthreads; i++){
        mutex_local_go[i] = PTHREAD_MUTEX_INITIALIZER;
    }
}

CP::~CP(){
    delete dataF;
    //delete player;
    player = 0;
    for(int i=0; i<nthreads; i++){
        delete thread_player[i];
    }  
}
void CP::init_offline_data(){
    std::stringstream ss;

    rand_pool.resize(nthreads);

    for(int i=0; i<nthreads; i++){
        //read share of rand value
        ss.str("");
        ss << PREP_DATA_PREFIX << "/Rands-p-P" << mynum;
        if (i){
            ss << "-" << i;
        }
        rand_pool[i].open(ss.str().c_str(), ios::in | ios::binary);
    }

}

void CP::close_offline_data_stream(){
    for(int i=0; i<nthreads; i++){
        rand_pool[i].close();
    }
    
}


void CP::benchmark(){
    cout << "************** Start data Aggregation phase **************" << endl;
    //time measure tools 
    struct timeval t1;
    struct timeval t2;
    double cpu_time_used;

    std::vector<gfp> a(oM),mac(oM);
    bigint tmp;
    double R;

    gettimeofday(&t1, NULL);
    cout<<"The aggregation value is \n";
    open_and_check(share_histogram,a,mac);
    for(int i=0; i<oM; i++){
        // open_and_check(share_histogram[i],a,mac);
        to_bigint(tmp,a[i]);
        R = tmp.get_si();
        cout<<R<<"\t";
    }
    cout<<endl;
    gettimeofday(&t2, NULL);
    cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
    printf("Aggregation procedure: %d clients each with %d messages need  %f (ms) \n",uN,oM,cpu_time_used);

    size_t send_bytes = report_size();
    double KB_bytes = double(send_bytes*2)/1000;
    printf("Aggregation procedure: \tcommu:\t%f\t(KB)\n\n",KB_bytes);

    printf("Output communication: \tcommu:\t%ld\t(Byte)\n\n",sizeof(R));


    cout << "************** End data Aggregation phase **************" << endl;
}

size_t CP::report_size(){
    size_t sent = 0;
    for(int i=0; i<nthreads*communication_multiplier; i++){
        sent += thread_player[i]->sent;
        thread_player[i]->sent = 0;
    }
    return sent;
}

void* CP::thread_Broadcast_single(void* arg){
    thread_sender_info* data = static_cast<thread_sender_info*>(arg);
    CP* obj = data->obj;

    if(data->send_func){
        obj->Broadcast_S_single(*(data->o), data->t_id, data->player_no, true);
    }else{
        obj->Broadcast_R_single(*(data->o), data->t_id, data->player_no, true);
    }
    pthread_exit(NULL);
}


void CP::Broadcast_S_single(octetStream& o, int father_num, int player_no, bool multi_thread){
    TimeScope ts(commu_timer[2*father_num*nparties + player_no]);

    if(player_no > mynum){
        o.Send(CP_sockets[father_num][player_no]);
    }

    if(player_no < mynum){
        o.Send(CP_sockets[nthreads + father_num][player_no]);
    }

    //thread_player[father_num]->sent += o.get_length() * (nparties - 1); it's father thread do this functionality

    if(multi_thread){
        pthread_mutex_lock(&mutex_local_go[father_num]); 
        local_Go[father_num]++;
        pthread_mutex_unlock(&mutex_local_go[father_num]);
    }else{
        thread_player[father_num]->sent += o.get_length();
    }
}

void CP::Broadcast_R_single(octetStream& o, int father_num, int player_no, bool multi_thread){
    TimeScope ts(commu_timer[2*father_num*nparties + nparties + player_no]);
    o.reset_write_head();

    if(player_no < mynum){
        o.Receive(CP_sockets[father_num][player_no]);
    }

    if(player_no > mynum){
        o.Receive(CP_sockets[nthreads + father_num][player_no]);
    }

    if(multi_thread){
        pthread_mutex_lock(&mutex_local_go[father_num]); 
        local_Go[father_num]++;
        pthread_mutex_unlock(&mutex_local_go[father_num]);
    }  
}

void CP::Broadcast_S_and_R(vector<octetStream>& o, int thread_num){
    /*
    *   Implementation 3
    */
    local_Go[thread_num] = 0;

    pthread_t* t = new pthread_t[nparties*2];
    std::vector<thread_sender_info> thread_receive_data(nparties);
    std::vector<thread_sender_info> thread_send_data(nparties);
    for(int i=0; i<nparties; i++){
        if(i == mynum){
            continue;
        }

        thread_receive_data[i].obj = this;
        thread_receive_data[i].t_id = thread_num;
        thread_receive_data[i].o = &(o[i]);
        thread_receive_data[i].player_no = i;
        thread_receive_data[i].send_func = false;
        pthread_create(&t[i], NULL,thread_Broadcast_single, (void*) &thread_receive_data[i]);
    }

    for(int i=0; i<nparties; i++){
        if(i == mynum){
            continue;
        }

        thread_send_data[i].obj = this;
        thread_send_data[i].t_id = thread_num;
        thread_send_data[i].o = &(o[mynum]);
        thread_send_data[i].player_no = i;
        thread_send_data[i].send_func = true;
        pthread_create(&t[i+nparties], NULL,thread_Broadcast_single, (void*) &thread_send_data[i]);
    }



    while(local_Go[thread_num] < (nparties-1)*2){
        usleep(5);
    }

    delete t;
}


template <class T>
void CP::open_and_check(const Share<T>& share_value, T& a, T& mac){
    if(player == 0){
        throw runtime_error("The p2p socket has been expired");
    }
    vector<Share<T>> res_share(nparties);
    vector<octetStream> vec_shares(nparties);
    share_value.pack(vec_shares[mynum]);
    player->Broadcast_Receive(vec_shares);

    for(int k=0;k< nparties;k++){
        res_share[k].unpack(vec_shares[k]);
    }
    check_share(res_share,a,mac,nparties,keyp);
}

template <class T>
void CP::delay_open_and_check(const Share<T>& share_value, T& a, int thread_num){
    if(thread_player[thread_num] == 0){
        throw runtime_error("The p2p socket has been expired");
    }
    vector<Share<T>> res_share(nparties);
    vector<octetStream> vec_shares(nparties);
    share_value.pack(vec_shares[mynum]);
    thread_player[thread_num]->Broadcast_Receive(vec_shares);

    std::vector<PSUCA::W2C_mac>& wait_queue = W2C_mac_queue[thread_num];
    int& count = n_wait2Check[thread_num];

    for(int k=0;k< nparties;k++){
        res_share[k].unpack(vec_shares[k]);
        wait_queue[count].value.add(res_share[k].get_share());
        wait_queue[count].mac.add(res_share[k].get_mac());
    }

    a.assign(wait_queue[count].value);
    count++;
    if(count == PSUCA::max_w2c){
        batch_mac_check(thread_num);
    }
}

void CP::init_wait_to_check_buffer(){
    n_wait2Check.resize(nthreads*communication_multiplier);
    W2C_mac_queue.resize(nthreads*communication_multiplier);

    for(int i=0; i<nthreads*communication_multiplier; i++){
        n_wait2Check[i] = 0;
        W2C_mac_queue[i].resize(PSUCA::max_w2c+10);
    }
}


template <class T>
void CP::delay_open_and_check(const std::vector<Share<T>>& share_value, std::vector<T>& a, int thread_num){
    if(thread_player[thread_num] == 0){
        throw runtime_error("The p2p socket has been expired");
    }

    int size_array = share_value.size();
    if(!size_array){
        return;
    }

    std::vector<PSUCA::W2C_mac>& wait_queue = W2C_mac_queue[thread_num];
    int& count = n_wait2Check[thread_num];

    if((size_array+count) >= PSUCA::max_w2c){
        batch_mac_check(thread_num);
    }

    vector<Share<T>> res_share(nparties);
    vector<octetStream> vec_shares(nparties);

    for(int i=0; i<size_array; i++){
        share_value[i].pack(vec_shares[mynum]);
    } 

    
    if(local_envs){
        thread_player[thread_num]->Broadcast_Receive(vec_shares);
    }else{
        thread_player[thread_num]->sent += vec_shares[mynum].get_length() * (nparties - 1);
        Broadcast_S_and_R(vec_shares, thread_num);
    }
    

    for(int i=0; i<size_array; i++){
        for(int k=0; k<nparties; k++){
            res_share[k].unpack(vec_shares[k]);
            wait_queue[count].value.add(res_share[k].get_share());
            wait_queue[count].mac.add(res_share[k].get_mac());
        }
        a[i].assign(wait_queue[count].value);
        count ++;
    }
}

template <class T>
void CP::_delay_open_and_check(const std::vector<Share<T>>& share_value, std::vector<T>& a, int n_elements, int start_share, int start_a, int thread_num){
    if(thread_player[thread_num] == 0){
        throw runtime_error("The p2p socket has been expired");
    }

    std::vector<PSUCA::W2C_mac>& wait_queue = W2C_mac_queue[thread_num];
    int& count = n_wait2Check[thread_num];

    if((n_elements+count) >= PSUCA::max_w2c){
        batch_mac_check(thread_num);
    }

    vector<Share<T>> res_share(nparties);
    vector<octetStream> vec_shares(nparties);

    for(int i=start_share; i<start_share+n_elements; i++){
        share_value[i].pack(vec_shares[mynum]);
    } 

    if(local_envs){
        thread_player[thread_num]->Broadcast_Receive(vec_shares);
    }else{
        thread_player[thread_num]->sent += vec_shares[mynum].get_length() * (nparties - 1);
        Broadcast_S_and_R(vec_shares, thread_num);
    }
    
    for(int i=start_a; i<start_a+n_elements; i++){
        for(int k=0; k<nparties; k++){
            res_share[k].unpack(vec_shares[k]);
            wait_queue[count].value.add(res_share[k].get_share());
            wait_queue[count].mac.add(res_share[k].get_mac());
        }
        a[i].assign(wait_queue[count].value);
        count ++;
    }
}
void CP::batch_mac_check(int thread_num){
    gfp res;
    if(thread_num == -1){
        for(int k=0; k<nthreads*communication_multiplier; k++){
            for(int i=0; i<n_wait2Check[k]; i++){
                res.mul(W2C_mac_queue[k][i].value,keyp);
                if (!res.equal(W2C_mac_queue[k][i].mac))
                    {
                      cout << "Value:      " << W2C_mac_queue[k][i].value << endl;
                      cout << "Input MAC:  " << W2C_mac_queue[k][i].mac << endl;
                      cout << "Actual MAC: " << res << endl;
                      cout << "MAC key:    " << keyp << endl;
                      throw mac_fail();
                    }
                W2C_mac_queue[k][i].value.assign(0);
                W2C_mac_queue[k][i].mac.assign(0);
            }
            n_wait2Check[k] = 0;
        } 
    }else{
        std::vector<PSUCA::W2C_mac>& wait_queue = W2C_mac_queue[thread_num];
        int& count = n_wait2Check[thread_num];

        for(int i=0; i<count; i++){
            res.mul(wait_queue[i].value,keyp);
            if (!res.equal(wait_queue[i].mac))
                {
                  cout << "Value:      " << wait_queue[i].value << endl;
                  cout << "Input MAC:  " << wait_queue[i].mac << endl;
                  cout << "Actual MAC: " << res << endl;
                  cout << "MAC key:    " << keyp << endl;
                  throw mac_fail();
                }
            wait_queue[i].value.assign(0);
            wait_queue[i].mac.assign(0);
        }
        count = 0;
    }
    
}
template <class T>
void CP::thread_open_and_check(const std::vector<Share<T>>& share_value, std::vector<T>& a, std::vector<T>& mac, int thread_num){
    if(thread_player[thread_num] == 0){
        throw runtime_error("The p2p socket has been expired");
    }

    int size_array = share_value.size();
    if(!size_array){
        return;
    }

    vector<Share<T>> res_share(nparties);
    vector<octetStream> vec_shares(nparties);

    for(int i=0; i<size_array; i++){
        share_value[i].pack(vec_shares[mynum]);
    } 

    thread_player[thread_num]->Broadcast_Receive(vec_shares);
    
    for(int i=0; i<size_array; i++){
        for(int k=0; k<nparties; k++){
            res_share[k].unpack(vec_shares[k]);
        }
        check_share(res_share,a[i],mac[i],nparties,keyp);
    }
}

template <class T>
void CP::open_and_check(const vector<Share<T>>& share_value, vector<T>& a, std::vector<T>& mac){
    if(player == 0){
        throw runtime_error("The p2p socket has been expired");
    }

    int size_array = share_value.size();
    if(!size_array){
        return;
    }

    vector<Share<T>> res_share(nparties);
    vector<octetStream> vec_shares(nparties);

    for(int i=0; i<size_array; i++){
        share_value[i].pack(vec_shares[mynum]);
    } 
    player->Broadcast_Receive(vec_shares);
    for(int i=0; i<size_array; i++){
        for(int k=0; k<nparties; k++){
            res_share[k].unpack(vec_shares[k]);
        }
        check_share(res_share,a[i],mac[i],nparties,keyp);
    }
}



void CP::start(){
    benchmark();
}

DP_connector::DP_connector(int _mynum,int pnb,int my_port, int _num_dp_players, int _oM, int _uN, int _nthreads){
    oM = _oM;
    uN = _uN;
    dataF = 0;
    player = 0;
    nthreads = _nthreads;
    init(_mynum,pnb,my_port,_num_dp_players);
    sent = 0;
}
void DP_connector::init(int _mynum,int pnb,int _my_port, int _num_dp_players)
{  
    nplayers = _num_dp_players;
    mynum=_mynum;
    portnum_base=pnb;
    if(_my_port == DP_connector::DEFAULT_PORT){
      my_port = portnum_base+DP_connector::OFFSET_PORT+mynum;
    }
    setup_server();
}

void DP_connector::key_init(gfp& _alphai,gfp& _keyp){
    alphai.assign(_alphai);
    keyp.assign(_keyp);
}
void DP_connector::player_init(Player* _player){
    player = _player;
}

DP_connector::~DP_connector()
{
    if (server != 0)
        delete server;
}



void DP_connector::setup_server()
{
  server = new ServerSocket(my_port);
  server->init();
}


void DP_connector::start(Data_Files* _df, std::vector<Share<gfp>>& share_histogram){
    dataF = _df;
    /*
    * Collect the data of each data party orderly
    */
    int i=0;
    int socket_num = -1;
    if (server == 0)
        throw runtime_error("The socket communication failure detection");


    /***********************************Start For benchmark*********************************/
    cout << "************** Start data Collection phase **************" << endl;
    //time measure tools 
    struct timeval t1;
    struct timeval t2;
    double cpu_time_used;
    double KB_bytes;
    
    for (i=1; i<=nplayers; i++)
    {
        cerr << "Waiting for Data Party " << i << endl;
        socket_num = server->get_connection_socket(i);
        cerr << "Connected to Data Party " << i << endl;
        
        send(socket_num, GO);

        // oM denote the number of buckets
        // uN denote the number of encoders
        share_histogram.clear();
        share_histogram.resize(oM);
  

        gettimeofday(&t1, NULL);
        share_value(share_histogram,socket_num);
        gettimeofday(&t2, NULL);
        cpu_time_used = (double)(t2.tv_sec-t1.tv_sec)*1000+(double)(t2.tv_usec-t1.tv_usec)/1000;
        printf("Encoder uploading procedure:\ttime:\t%f\t(ms)\t",cpu_time_used);
        
    
        size_t send_bytes = report_size();
        KB_bytes = send_bytes*2/1000;
        printf("\tcommu:\t%f\t(KB)\n\n",KB_bytes);

        KB_bytes = KB_bytes*1000/uN;
        printf("Local randomizer communication:  %f (byte) \n",KB_bytes);

        close(socket_num);
        socket_num = -1;
    }

    cout << "************** End Data Collection phase **************" << endl;
}

void DP_connector::send_to(int data_player,const octetStream& o,bool donthash) const
{
    TimeScope ts(timer);
    o.Send(data_player);
    if (!donthash)
        { blk_SHA1_Update(&ctx,o.get_data(),o.get_length()); }
    sent += o.get_length();
}

void DP_connector::receive_player(int data_player,octetStream& o,bool donthash) const{
    TimeScope ts(timer);
    o.reset_write_head();
    o.Receive(data_player);
    sent += o.get_length();
    if (!donthash)
        { blk_SHA1_Update(&ctx,o.get_data(),o.get_length()); }
}

template <class T>
bool DP_connector::share_value(Share<T>& x, int socket_num){
    if(socket_num == -1){
        throw runtime_error("The socket has been expired");
    }

    
    Share<T> a;
    T a_value,a_mac,y_value,tmp; //share value of a
    octetStream share_stream;

    if(!dataF->eof<T>(DATA_RAND)){
        dataF->get_one(DATA_MODP, DATA_RAND, a); //this should be changed as rand afterly
    }else{
        throw runtime_error("Cannot read the random share from the data files");
    }


    a_value = a.get_share();
    a_value.pack(share_stream);
    //  reveal a to data party
    send_to(socket_num,share_stream);
    share_stream.reset_write_head();
    //  receive x-a from data party
    receive_player(socket_num,share_stream);
    y_value.unpack(share_stream);

    //compute the data party to-share value x
    a_mac = a.get_mac();
    tmp.assign_zero();
    if(mynum == 0){
        a_value.add(y_value);
        tmp.mul(y_value,alphai);
        a_mac.add(tmp);
    }else{
        tmp.mul(y_value,alphai);
        a_mac.add(tmp);
    }

    x.set_share(a_value);
    x.set_mac(a_mac);

    return true;
}


size_t DP_connector::report_size(){
    size_t result = sent;
    sent = 0;
    return result;
}
template <class T>
bool DP_connector::share_value(std::vector<Share<T>>& des_vec, int socket_num){
    if(socket_num == -1){
        throw runtime_error("The socket has been expired");
    }

    int elements_size = oM*uN;
    std::vector<Share<T>> a_Array(elements_size);
    Share<T> tmp_share;
    T tmp, a_mac, y_value, a_value;

    octetStream share_stream;

    int j = 0;
    while ((j<elements_size) && (!dataF->eof<T>(DATA_RAND)))
    {
        dataF->get_one(DATA_MODP, DATA_RAND, a_Array[j]); //this should be changed as rand afterly
        j++;
    }

    if(j < elements_size)
        throw runtime_error("cannot read enough random share from offline file");

    for(int i=0; i<elements_size; i++){
        a_Array[i].get_share().pack(share_stream);
    }

    //  reveal a to data party
    send_to(socket_num,share_stream);
    share_stream.reset_write_head();
    //  receive x-a from data party
    receive_player(socket_num,share_stream);

    for(int m=0; m<oM; m++){
        des_vec[m].assign_zero();
        for(int i=0; i<uN; i++){
            y_value.unpack(share_stream);
            //compute the data party to-share value x
            a_mac = a_Array[m*uN+i].get_mac();
            a_value = a_Array[m*uN+i].get_share();
            tmp.assign_zero();

            if(mynum == 0){
                a_value.add(y_value);
                tmp.mul(y_value,alphai);
                a_mac.add(tmp);
            }else{
                tmp.mul(y_value,alphai);
                a_mac.add(tmp);
            }

            tmp_share.set_share(a_value);
            tmp_share.set_mac(a_mac);
            des_vec[m] += tmp_share;
        }
    }
    return true;
}