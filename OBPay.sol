pragma solidity ^0.4.19;

import "./altbn_128.sol";

contract OBPay {

	using alt_bn128 for *; 

	uint constant k = 60;
	struct Task{
		address user;
		address worker;
        string f_des;
        uint256 h_s;
        string P_des;
        uint256 R_val;
        uint256 b_val;
        uint256 index;
        uint256[k] T_val;
        uint256[k] P2_val;
        uint256[2] h_val;
        uint256[2] C_val;
        uint256 key_val;
        uint256 r_val;
        
    }
    
    struct CM{
        uint256[k] h_val;
        uint256[2] C_val;
    }
    
	uint constant v = 100;
	uint constant v_f= k * v;
	uint constant v_g = 2 * k * v;
    Task [] task;
	Task tmpTask;

    uint public i;
    uint public j;
    
    uint256[2] public baseP;
    uint256[2] public baseQ;
    uint256 private start;
	
	//constructor, automatically executed
	function OBPay() public {
	//** add hard-coded values as neccessary here ***//
		baseP = peddersenBaseP();
        baseQ = peddersenBaseQ();
	}
	function peddersenBaseP() public view returns (uint256[2] point) {
        bytes32 h = keccak256("P");
        alt_bn128.G1Point memory g1p = alt_bn128.uintToCurvePoint(uint256(h));
        return [g1p.X, g1p.Y];
    }
    
    function peddersenBaseQ() public view returns (uint256[2] point) {
        bytes32 h = keccak256("Q");
        alt_bn128.G1Point memory g1p = alt_bn128.uintToCurvePoint(uint256(h));
        return [g1p.X, g1p.Y];
    }
	
	//function to submit the task
	function submitTask(string f_des, uint256 h_s, string P_des, uint256 R_val, uint256 b_val, uint256[k] T_val, uint256[k] P2_val ) public  {
		tmpTask.user = msg.sender;
	    tmpTask.f_des = f_des;
	    tmpTask.h_s = h_s;
	    tmpTask.P_des = P_des;
	    tmpTask.R_val = R_val;
	    tmpTask.b_val = b_val;
	    for(i = 0; i < k; i++)
	    {
	        tmpTask.T_val[i] = T_val[i];
	        tmpTask.P2_val[i] = P2_val[i];
	    }
		task.push(tmpTask);
	}
	
	//function to find the place of user
	function find(address user) public returns (uint256){
		uint256 i;
		for( i = 0; i < task.length; i++)
		{
			if(task[i].user == user)
			{
				return i;
			}
		}
		return 0;
	}
	
	
	//function to get the task
	function getTask (address user) public view returns(string f_des, uint256 h_s, string P_des, uint256 R_val, uint256 b_val, uint256[k] T_val, uint256[k] P2_val){
	    uint256 l;
		l = find(user);
		return (task[l].f_des, task[l].h_s, task[l].P_des, task[l].R_val, task[l].b_val, task[l].T_val, task[l].P2_val);
	}
	
	//function to compute the commitment
	function computeCM(uint256 key_val, uint256 r_val) public view returns(uint256[2] commitment){
	
	    alt_bn128.G1Point memory P_point;
	    alt_bn128.G1Point memory Q_point;
	    // Generate left point r * Q
        P_point.X = baseP[0];
        P_point.Y = baseP[1];
        alt_bn128.G1Point memory lf = alt_bn128.mul(P_point, r_val);
        
        
        Q_point.X = baseQ[0];
        Q_point.Y = baseQ[1];
        // Generate right point key * P
        alt_bn128.G1Point memory rt = alt_bn128.mul(Q_point, key_val);

        // Generate C = key * P + r * Q
        alt_bn128.G1Point memory C_point = alt_bn128.add(lf, rt);
        commitment[0] = C_point.X;
        commitment[1] = C_point.Y;
        return commitment;
        
	}
	
	//function to submit the commitment
	function submitCM(address user, uint256[2] h_val, uint256[2] C_val) public payable returns (bool){
	//** the function of submitCM **//
		require(msg.value >= v_g);
		uint256 l;
		l = find(user);
		if(task[l].worker == 0)
		{
			task[l].worker = msg.sender;
			
			for(i = 0; i <2; i++)
			{
			    task[l].h_val[i] = h_val[i];
				task[l].C_val[i] = C_val[i];
			}
		}
		else
		{
			require(msg.sender == task[l].worker);
			
			task[l].h_val = h_val;
			for(i = 0; i <2; i++)
			{
				task[l].C_val[i] = C_val[i];
			}
		}
		
		return true;
	}
	
	//function to get the commitment
	function getCM(address user) public view returns (uint256[2] h_val, uint256[2] C_val){
	     uint256 l;
	     l = find(user);
		 return(task[l].h_val, task[l].C_val);
         
    }
    
	//function to pay for the request
    function payRequest (address user) public payable returns (bool){
        uint256 l;
        l = find(user);
		require((msg.sender == task[l].user) && (msg.value >= v_f));
        return true;
        
    }
	
	//function to submit the proof
	function submitProof(address user, uint256 key_val, uint256 r_val) public returns (bool){
	    uint256 l;
	    l = find(user);
		require(msg.sender == task[l].worker);
	    var (, commitment) = getCM(user);
	    if(verify(key_val, r_val, commitment))
	    {
	        task[l].key_val = key_val;
	        task[l].r_val = r_val;
	        task[l].worker.transfer(v_f);
	        start = now; //now is an alias for block.timestamp, not really "now"
	    }
	    return true;
	    
	}
	
	//function to obtain the proof
	function getProof(address user) public view returns (uint256, uint256){	    
		  uint256 l;
		  l = find(user);
		  require(msg.sender == task[l].user);
	      return (task[l].key_val, task[l].r_val);
	}
	
	//function to verify the proof
	function verify(uint256 key_val, uint256 r_val, uint256[2] commitment) public view returns (bool){
	    alt_bn128.G1Point memory P_point;
	    alt_bn128.G1Point memory Q_point;
	    // Generate left point r * Q
        P_point.X = baseP[0];
        P_point.Y = baseP[1];
        alt_bn128.G1Point memory lf = alt_bn128.mul(P_point, r_val);
        
        
        Q_point.X = baseQ[0];
        Q_point.Y = baseQ[1];
        // Generate right point key * P
        alt_bn128.G1Point memory rt = alt_bn128.mul(Q_point, key_val);

        // Generate C = key * P + r * Q
        alt_bn128.G1Point memory C_point = alt_bn128.add(lf, rt);

        return (C_point.X == commitment[0] && C_point.Y == commitment[1]);
	}
	
	// function to submit claim proof
	function submitCP(address user, uint256 c_val, uint256[2] pi_c) public returns (bool){
	    uint256 x_val;
		uint256 l;
		alt_bn128.G1Point memory P_pi_c;
		alt_bn128.G1Point memory P_h_val;
		alt_bn128.G1Point memory tmp;
		l = find(user);
	    if(msg.sender == task[l].user)
	    {
    	        P_pi_c.X = pi_c[0];
    	        P_pi_c.Y = pi_c[1];
    	        P_h_val.X = task[l].h_val[0];
    	        P_h_val.Y = task[l].h_val[1];
    	        tmp = alt_bn128.mul(P_pi_c, c_val);
    	        if( tmp.X == P_h_val.X && tmp.Y == P_h_val.Y)
    	        {
    	           x_val = decrypt(c_val, task[l].key_val);
    	           for(j = 0; j < k; j++)
    	           {
    	               if(uint256(keccak256(x_val)) == task[l].P2_val[j])
    	               {
    	                   return false;
    	               }
    	           }
    	           msg.sender.transfer(v_g);
    	           return true;
    	        }
	    }
	    else if (msg.sender == task[l].worker)
	    {
	        if(now > start + 10 minutes)
	        {
	            msg.sender.transfer(v_g);
	        }
	    }
	}
	
	// function to both encrypt and decrypt text chunks using key
	function symmecrpto (uint256[k] plaintext, uint256 key) private view returns (uint256[k]){
	    uint256 l;
	    uint256[k] ciphertext;
        for (l = 0; l < k; l++){
            ciphertext[l] = uint256(keccak256(l, key)) ^ plaintext[l];
        }
        return ciphertext;
    }
    
    // function to decrypt only one text chunk using key
	function decrypt (uint256 plaintext, uint256 key) private view returns (uint256){
	    uint256 ciphertext;
        ciphertext = uint256(keccak256(1, key)) ^ plaintext;
        return ciphertext;
    }

}
