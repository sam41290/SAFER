/*******************************************************************************
 *
 * Value distributions can be on scalar or categorical data. For scalar data,
 * distributions can be maintainted using histograms. For categorical data, you
 * need essentially a counted set, i.e., a set that consists of elements
 * together with a count of how many times they occur. However, with categorical
 * data, it is often the case that there are far too many categories, e.g., IP
 * addresses. So, we typically want to maintain only those items that occur
 * frequently. In other words, we should use MFUTable.
 *
 * The next question is whether there is analog to how frequency distributions
 * chain counts, with counts over smaller timescales linking to counts over
 * larger timescales. The obvious analog of this for value distributions ends up
 * being useless. Consider the example of an MFUTable for maintaining the top N
 * ports accepting connections in the last t seconds. One can think of linking
 * this to an MFUTable that maintains the top M ports (M >> N) over 10t seconds.
 * But this does not work for the following reason. In particular, the MFUTable
 * for t seconds is meaningful only if the information it contains is stable
 * over the long term. If not, this table does not help characterize normal
 * behavior. Now, if the information in the table is stable, then, each of the
 * entries in tha table for t seconds will all appear in the 10t table. Thus,
 * the content of the t-second table is simply the top N among the M entries in
 * the 10t-second table.
 *
 * But a different way of chaining is still meaningful. In particular, an MFU
 * table with coarse categories can be linked to others with finer granularity
 * categories. For instance, one could have a higher level MFU table that has
 * bins corresponding to 1-100, 101-200, 201-300, and so on. From each of these
 * bins, one can link to another histogram that considers further subdivisions.
 * For instance, the 1-100 bin may be connected to another historgram that
 * considers each of the ports 1 through 100 separately. Now, as connections
 * come in, they are entered into the finer granularity MFUTable. As and when
 * this table is purged of stale entries, the counts can be accumulated in the
 * next level table. To ensure that count propagation does not get delayed
 * indefinitely, we need to set a time limit as well as capacity utilization
 * based criteria for purging.
*******************************************************************************/
