
**Claims regarding parallel composition.**

Consider the case of the parallel composition of $n$ differentially private algorithms. Intuitively, since the input data of different algorithms are independent with each other, we could partition the input dataset into $n$ independent datasets. The change of one element could only influence one of these independent datasets. Therefore, if every private algorithm is $(\varepsilon,\delta)$-differentially private, then the composed private algorithm is $(\varepsilon,\delta)$-differentially private. We give a formal proof as follows.

+ **Theorem** Let $M_i$ each provide $(\varepsilon,\delta)$-diﬀerential privacy. Let $D_i$ be arbitrary disjoint subsets of the input domain $D$. For any input dataset $X$, the sequence of $M_i (X\cap D_i)$ provides $(\varepsilon,\delta)$-diﬀerential privacy.

+ **Proof**.  Let $X$, $X^\prime$ be neighboring datasets. Suppose that they are both divided into $n$ subsets of disjoint data, where $X_i=X\cap D_i$ and  $X_i^\prime=X^\prime\cap D_i$. Without loss of generality, $X$ and $X^\prime$ are only different between $X_1$ and $X_1^\prime$ for one element. For any $r_1 \subseteq Range(M_1)$, We have:$$Pr[M_1(X_1)\in r_1] \leq e^{\varepsilon} Pr[M_1(X_1^\prime)\in r_1]+\delta.$$
For any $r \subseteq Range(M) $ and $r_i \subseteq Range(M_i) $, where $M$ is the sequence of $M_i$, the probability of output from the sequence of $M(X)$ is
$$\begin{aligned}
Pr[M(X)\in r]&=\prod_{i=1}^n Pr[M_i(X_i)\in r_i]\\
&=\prod_{i=2}^n Pr[M_i(X_i)\in r_i]Pr[M_1(X_1\in r_1]\\
&\leq\prod_{i=2}^n Pr[M_i(X_i)\in r_i](e^{\varepsilon} Pr[M_1(X_1^\prime)\in r_1]+\delta)\\
&=e^{\varepsilon}Pr[M_1(X_1^\prime)\in r_1]\prod_{i=2}^n  Pr[M_i(X_i)\in r_i]  +\delta\prod_{i=2}^n Pr[M_i(X_i)\in r_i]\\
&\leq e^{\varepsilon}Pr[M(X^\prime)\in r]+\delta,
\end{aligned}$$
which completes the proof.

Other references: https://crypto.stackexchange.com/questions/48925/parallel-composition-of-epsilon-delta-differential-privacy; P33 Example 3.2 of ” The Algorithmic Foundations of Differential Privacy”.
