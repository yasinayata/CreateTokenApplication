using System;
using System.Collections.Generic;
using System.Text;

namespace Models
{
    //************************************ OperationResult **********************************
    #region OperationResult
    public class OperationResult
    {
        public bool Result { get; set; }
        public string Message { get; set; }
        //public List<Exception> Exceptions { get; set; } //Islem sirasinda alinan hata (lar) varsa...

        public OperationResult()
        {
            this.Result = true;
            this.Message = "Successful";
            //this.Exceptions = new List<Exception>();    //Exception bos olarak olusturuluyor...
        }
    }

    public class OperationResult<T> : OperationResult
    {
        public T Data { get; set; }
    }
    #endregion OperationResult

}
