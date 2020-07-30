// (C) 2018 University of NKU. Free for used

/*
 * ComputationParty.h
 *
 */

#ifndef COMPUTATION_PARTY_H_
#define COMPUTATION_PARTY_H_


/*
 * @Func Computation Party
 * @Params of the Class CP 
 *		@nparties 			number of the parties
 *		@ndparties 			number of the data parties
 *      @pnbase  			Port number base to attempt to start connections from 
 *		@mynum			    the NO. mark of the current party
 *		@my_port			the port that the server sokcet listening
 *		@hostname			Host where Server.x is running to coordinate startup (default: localhost). Ignored if --ip-file-name is used.
 *		@playerNames		Names server, help to identify the other machine in the whole connected network
 *		@player  			The wrapped socket for the p2p communication
 *    	@uN                 number of unique items
 */

#include <string>
#include <vector>
#include <fstream>
#include <pthread.h>

#include "Networking/Player.h"
#include "Networking/ServerSocket.h"
#include "Tools/time-func.h"
#include "Tools/sha1.h"

#include "ElGamal_openssl.h"


class CP
{
private:
	int nparties; 
	int ndparties;
	int pnbase; 
	int mynum; 
	int my_port; 
	std::string hostname;
	int uN;
	int n_bins;

	/*
	*	core functionality data structure
	*/
	std::vector<BIGNUM*> share_HS;
	std::vector<ElGamalCiphertext> share_CHS;

	std::vector<ElGamal*> sys;

	/*
	*	Network Parameters
	*/
	Player* player;
	std::vector<Player*> thread_player;
	vector<vector<int>> CP_sockets;
	mutable vector<Timer> commu_timer;

	/*
	*	Accuracy parameter
	*/
	double delta;
	double epsilon;
	int param_N;
  	

  // for multithread
  int nthreads;
	pthread_mutex_t mutex_go;
	int Go;
	vector<pthread_mutex_t> mutex_local_go;
	vector<int> local_Go;

  // openssl math aux
  vector<BN_CTX*> bn_ctx;

	static constexpr int port_increase = 75;
	// for communcation thread: 0 for send and 1 for receive
	static constexpr int communication_multiplier = 2;
public:
    CP(int argc, const char** argv);
    void start();
    ~CP();


    // /*
    // *	Aggregating input phase functionality
    // */
    void _key_gen(int thread_num = 0, bool multi_thread = false);
    static void* thread_key_gen(void* arg);
    void key_gen();



    void get_encrypted_HS(vector<BIGNUM *>& sh_HS, vector<ElGamalCiphertext>& sh_CHS, int start, int internal, int thread_num = 0, bool multi_thread = false);
    static void* thread_get_encrypted_HS(void* arg);
    void multi_thread_get_encrypted_HS(vector<BIGNUM *>& sh_CH, vector<ElGamalCiphertext>& sh_CHS);

    // /*
    // *	Shuffling phase functionality
    // */
    void shuffling(vector<ElGamalCiphertext>& sh_CHS, int start, int internal, int thread_num = 0, bool multi_thread = false);
    static void* thread_shuffling(void* arg);
    void multi_thread_shuffling(vector<ElGamalCiphertext>& sh_CHS);

    // /*
    // *	Decryption phase functionality
    // */
    void decrypt(vector<ElGamalCiphertext>& sh_CHS, int start, int internal, int thread_num = 0, bool multi_thread = false);
    static void* thread_decrypt(void* arg);
    void multi_thread_decrypt(vector<ElGamalCiphertext>& sh_CHS);

    // /*
    // * Output phase functionality
    // */
    int Output(vector<ElGamalCiphertext>& sh_CHS);

    /*
    * Auxiliary functionality
    */
    size_t report_size();
};


/*
 * @Func The wrapped communication class with data party
 * @Params of the Class DP_connector
 * 		@default_port 		default receive port of the DP_connector
 *		@nplayers 			number of the data parties
 *      @portnum_base  		Port number base to attempt to start connections from 
 *		@mynum				the NO. mark of the current party(numbered in computation party)
 *		@my_port			the server listening port
 *    	@uN                 number of unique items
 */


class DP_connector
{
private:
  	int n_bins;
  	int portnum_base;
  	int mynum;
  	int my_port;
  	int nplayers;

  	void setup_server();
  	// for safe socket communication
  	mutable blk_SHA_CTX ctx;
  	mutable size_t sent;
  	mutable Timer timer;

    BIGNUM* mod_q;

    // openssl math aux
    BN_CTX* bn_ctx;
public:
	mutable ServerSocket* server;

	DP_connector():portnum_base(-1), mynum(-1), nplayers(-1),server(0){
		n_bins = 0;
		sent = 0;
    bn_ctx = BN_CTX_new();
    mod_q = BN_new();
	}
	void init(int _n_bins, int _mynum,int pnb,int my_port, int _nplayers, const BIGNUM* q);
  ~DP_connector();

	void start(std::vector<BIGNUM*>& sh_HS);

	bool data_collection(int socket_num, std::vector<BIGNUM*>& sh_HS);

	size_t report_size();

	// Send an octetStream to data player 
 	void send_to(int data_player,const octetStream& o,bool donthash=false) const;

 	// receive an octetstream from data player 
  void receive_from(int data_player,octetStream& o,bool donthash=false) const;

public:
  	static const int DEFAULT_PORT = -1;
  	static const int OFFSET_PORT = 2000;
};


#endif /* COMPUTATION_PARTY_H_ */
