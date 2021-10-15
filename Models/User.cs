using System;
using System.Collections.Generic;
using System.Text;

namespace Models
{
    public class User
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Surname { get; set; }
        public string Company { get; set; }
        public string Application { get; set; }
        public string Ip { get; set; }
        public string CreatedDateTime { get; set; }
        public string ExpirationDateTime { get; set; }
    }
}
